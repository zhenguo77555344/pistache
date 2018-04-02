#include <iostream>
#include <memory>
#include <type_traits>
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <atomic>

#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>

bool make_non_blocking(int sfd)
{
    int flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1) return false; 

    flags |= O_NONBLOCK;
    int ret = fcntl (sfd, F_SETFL, flags);
    if (ret == -1) return false;

    return true;
}

#define TRY(...) \
    do { \
        auto ret = __VA_ARGS__; \
        if (ret < 0) { \
            const char* str = #__VA_ARGS__; \
            std::ostringstream oss; \
            oss << str << ": "; \
            if (errno == 0) { \
                oss << gai_strerror(ret); \
            } else { \
                oss << strerror(errno); \
            } \
            throw std::runtime_error(oss.str()); \
        } \
    } while (0)

#define TRY_RET(...) \
    [&]() { \
        auto ret = __VA_ARGS__; \
        if (ret < 0) { \
            const char *str = #__VA_ARGS__; \
            std::ostringstream oss; \
            oss << str << ": " << strerror(errno); \
            throw std::runtime_error(oss.str()); \
        } \
        return ret; \
    }(); \
    (void) 0

namespace detail
{
    // @Improvement use the detector pattern
    template<typename Enum>
    struct HasNone {
        template<typename U>
        static auto test(U *) -> decltype(U::None, std::true_type());

        template<typename U>
        static auto test(...) -> std::false_type;

        static constexpr bool value =
            std::is_same<decltype(test<Enum>(0)), std::true_type>::value;
    };
}

template<typename T>
class Flags {
public:
    using Type = typename std::underlying_type<T>::type;

    static_assert(std::is_enum<T>::value, "Flags only works with enumerations");
    static_assert(detail::HasNone<T>::value, "The enumartion needs a None value");
    static_assert(static_cast<Type>(T::None) == 0, "None should be 0");

    Flags() : val(T::None) {
    }

    Flags(T val) : val(val)
    {
    }

#define DEFINE_BITWISE_OP_CONST(Op) \
    Flags<T> operator Op (T rhs) const { \
        return Flags<T>( \
            static_cast<T>(static_cast<Type>(val) Op static_cast<Type>(rhs)) \
        ); \
    } \
    \
    Flags<T> operator Op (Flags<T> rhs) const { \
        return Flags<T>( \
            static_cast<T>(static_cast<Type>(val) Op static_cast<Type>(rhs.val)) \
        ); \
    }
    
    DEFINE_BITWISE_OP_CONST(|)
    DEFINE_BITWISE_OP_CONST(&)
    DEFINE_BITWISE_OP_CONST(^)

#undef DEFINE_BITWISE_OP_CONST

#define DEFINE_BITWISE_OP(Op) \
    Flags<T>& operator Op##=(T rhs) { \
        val = static_cast<T>( \
                  static_cast<Type>(val) Op static_cast<Type>(rhs) \
              ); \
        return *this; \
    } \
    \
    Flags<T>& operator Op##=(Flags<T> rhs) { \
        val = static_cast<T>( \
                  static_cast<Type>(val) Op static_cast<Type>(rhs.val) \
              ); \
        return *this; \
    }

    DEFINE_BITWISE_OP(|)
    DEFINE_BITWISE_OP(&)
    DEFINE_BITWISE_OP(^)

#undef DEFINE_BITWISE_OP

    bool hasFlag(T flag) const {
        return static_cast<Type>(val) & static_cast<Type>(flag);
    }

    Flags<T>& setFlag(T flag) {
        *this |= flag;
        return *this;
    }

    Flags<T>& toggleFlag(T flag) {
        return *this ^= flag;
    }

    operator T() const {
        return val;
    }

private:
    T val;
};

#define DEFINE_BITWISE_OP(Op, T) \
    inline T operator Op (T lhs, T rhs)  { \
        typedef detail::UnderlyingType<T>::Type UnderlyingType; \
        return static_cast<T>( \
                    static_cast<UnderlyingType>(lhs) Op static_cast<UnderlyingType>(rhs) \
                ); \
    }

#define DECLARE_FLAGS_OPERATORS(T) \
    DEFINE_BITWISE_OP(&, T) \
    DEFINE_BITWISE_OP(|, T)

using Fd = int;

enum class NotifyOn {
    None = 0,

    Read     = 1,
    Write    = Read << 1,
    Hangup   = Read << 2,
    Shutdown = Read << 3
};

class Poller
{
public:
    struct Tag
    {
        constexpr Tag()
            : value_(0)
        {
        }

        constexpr Tag(uint64_t value)
            : value_(value)
        { }

        uint64_t value() const
        {
            return value_;
        }

    private:
        uint64_t value_;
    };

    struct Event {
        explicit Event(Tag tag) :
            tag(tag)
        { }

        Flags<NotifyOn> flags;
        Tag tag;
    };

    virtual void registerFd(Fd fd, Tag tag, Flags<NotifyOn> interest) = 0;
    virtual int poll(std::vector<Event>& events,
                     size_t maxEvents = 1024,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) const = 0;
};

bool operator==(Poller::Tag lhs, Poller::Tag rhs)
{
    return lhs.value() == rhs.value();
}

bool operator!=(Poller::Tag lhs, Poller::Tag rhs)
{
    return !(lhs == rhs);
}


class Epoll : public Poller
{
public:
    Epoll(size_t max = 128) {
       epoll_fd = TRY_RET(epoll_create(max));
    }

    void registerFd(Fd fd, Tag tag, Flags<NotifyOn> interest) override
    {
        struct epoll_event ev;
        ev.events = toEpollEvents(interest);
        ev.data.u64 = tag.value();

        std::cout << "Registering Fd(" << fd << ") with Tag(" << tag.value() << ")\n";

        TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev));
    }

    int poll(std::vector<Event>& events,
             size_t maxEvents = 1024,
             std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) const override
    {

        struct epoll_event evs[1024];

        int ready_fds = -1;
        do {
            ready_fds = epoll_wait(epoll_fd, evs, maxEvents, timeout.count());
        } while (ready_fds < 0 && errno == EINTR);

        if (ready_fds > 0) {
            for (int i = 0; i < ready_fds; ++i) {
                const struct epoll_event *ev = evs + i;

                const Tag tag(ev->data.u64);

                Event event(tag);
                event.flags = toNotifyOn(ev->events);
                events.push_back(event);
            }
        }

        return ready_fds;
    }

private:
    int toEpollEvents(Flags<NotifyOn> interest) const
    {
        int events = 0;

        if (interest.hasFlag(NotifyOn::Read))
            events |= EPOLLIN;
        if (interest.hasFlag(NotifyOn::Write))
            events |= EPOLLOUT;
        if (interest.hasFlag(NotifyOn::Hangup))
            events |= EPOLLHUP;
        if (interest.hasFlag(NotifyOn::Shutdown))
            events |= EPOLLRDHUP;

        return events;
    }
    Flags<NotifyOn> toNotifyOn(int events) const
    {
        Flags<NotifyOn> flags;

        if (events & EPOLLIN)
            flags.setFlag(NotifyOn::Read);
        if (events & EPOLLOUT)
            flags.setFlag(NotifyOn::Write);
        if (events & EPOLLHUP)
            flags.setFlag(NotifyOn::Hangup);
        if (events & EPOLLRDHUP) {
            flags.setFlag(NotifyOn::Shutdown);
        }

        return flags;
    }

    int epoll_fd;
};

class Evented
{
public:
    Evented(Poller::Tag tag)
        : tag_(tag)
    {
    }

    virtual void registerPoller(Poller& poller) const = 0;

    Poller::Tag tag() const
    {
        return tag_;
    }

private:
    Poller::Tag tag_;
};

class Socket : public Evented
{
public:
    Socket(Poller::Tag tag, Fd fd)
        : Evented(tag)
        , fd(fd)
    {
    }

    int64_t read(void *buffer, size_t size)
    {
        return ::recv(fd, buffer, size, 0);
    }

    void registerPoller(Poller& poller) const override
    {
        poller.registerFd(fd, tag(), NotifyOn::Read);
    }

private:
    Fd fd;
};

class Reactor
{
public:
    using Event = Poller::Event;

    class Handler
    {
    public:
        virtual void handleEvent(std::vector<Event> events) = 0;
    };

    void setHandler(const std::shared_ptr<Handler>& handler)
    {
        handler_ = handler;
    }

    Poller::Tag registerEvented(const Evented& evented)
    {
        evented.registerPoller(poller_);
        return evented.tag();
    };

    void run()
    {
        for (;;)
        {
            std::vector<Poller::Event> events;
            auto ready = poller_.poll(events);
            switch (ready)
            {
                case -1:
                    std::cout << "Blah!\n";
                    break;
                case 0:
                    continue;
                default:
                    std::cout << ready << " fds are ready!\n";
                    handler_->handleEvent(std::move(events));
            }
        }
    }

private:
    Epoll poller_;
    std::shared_ptr<Handler> handler_;
};

// For allocation, Pistache should have a range of reserved tags. User tags should not be able to use tags from that
// range
template<typename T>
class TagAllocator
{
public:
    TagAllocator(uint64_t initialValue = 1)
        : start(initialValue)
        , next(initialValue)
    {
    }

    void reserve(size_t size)
    {
        entries.reserve(size);
    }

    template<typename... Args>
    Poller::Tag allocate(Args&& ...args)
    {
        auto slot = next++;
        Poller::Tag tag(slot);

        auto value = std::make_shared<T>(tag, std::forward<Args>(args)...);
        entries.push_back(Entry(value, State::Used));
        return tag;
    }

    std::shared_ptr<T> get(Poller::Tag tag) const
    {
        auto index = tag.value() - start;
        if (index >= next)
            return nullptr;

        return entries[index].value;
    }

private:
    enum class State
    {
        Idle, Used
    };

    struct Entry
    {
        Entry()
            : value(nullptr)
            , state(State::Idle)
        {
        }

        Entry(std::shared_ptr<T> value, State state)
            : value(value)
            , state(state)
        {
        }

        std::shared_ptr<T> value;
        State state;
    };

    std::vector<Entry> entries;
    uint64_t start;
    uint64_t next;
};

class Listener;

class Transport : public Reactor::Handler
{
public:
    Transport(Reactor& reactor, Listener *const listener)
        : listener_(listener)
        , reactor_(reactor)
    {
    }

    void handleEvent(std::vector<Reactor::Event> events) override;
    
    Listener* const listener_;
    Reactor& reactor_;
};

class Listener : public Evented
{
public:
    friend class Transport;

    static constexpr auto Tag = Poller::Tag(1);

    Listener(Reactor& reactor)
        : Evented(Tag)
        , reactor(reactor)
        , transport(std::make_shared<Transport>(reactor, this))
        , socketAllocator(Tag.value() + 1)
    {
        reactor.setHandler(transport);
    }

    void registerPoller(Poller& poller) const override
    {
        poller.registerFd(listen_fd, Tag, NotifyOn::Read);
    }

    bool bind()
    {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM; 
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = 0;

        std::string host = "0.0.0.0";

        /* We rely on the fact that a string literal is an lvalue const char[N] */
        static constexpr size_t MaxPortLen = sizeof("65535");

        char port[MaxPortLen];
        std::fill(port, port + MaxPortLen, 0);
        std::snprintf(port, MaxPortLen, "%d", 12345);

        struct addrinfo *addrs;
        TRY(::getaddrinfo(host.c_str(), port, &hints, &addrs));

        int fd = -1;

        for (struct addrinfo *addr = addrs; addr; addr = addr->ai_next) {
            fd = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (fd < 0) continue;

            if (::bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
                close(fd);
                continue;
            }

            TRY(::listen(fd, 128));
            break;
        }

        if (fd == -1)
            return false;

        make_non_blocking(fd);
        listen_fd = fd;

        return true;
    }

    std::shared_ptr<Socket> accept()
    {
        struct sockaddr_in peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        int client_fd = ::accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (client_fd < 0) {
            throw std::runtime_error(strerror(errno));
        }

        make_non_blocking(client_fd);
        auto tag = socketAllocator.allocate(client_fd);
        auto socket = socketAllocator.get(tag);

        std::cout << "Connection accepted from Fd(" << client_fd << ")\n";
        return socket;
    }


private:
    Reactor& reactor;

    std::shared_ptr<Transport> transport;
    Fd listen_fd;
    TagAllocator<Socket> socketAllocator;

    std::shared_ptr<Socket> socket(Poller::Tag tag) const
    {
        return socketAllocator.get(tag);
    }
};

constexpr Poller::Tag Listener::Tag;

void Transport::handleEvent(std::vector<Poller::Event> events)
{

    for (const auto& event: events)
    {
        std::cout << "Event occured on Tag(" << event.tag.value() << ")\n";
        if (event.tag == Listener::Tag)
        {
            auto socket = listener_->accept();
            reactor_.registerEvented(*socket);
        }
        else
        {
            std::cout << "Event happened on a socket!\n";
            auto socket = listener_->socket(event.tag);

            char buffer[1024];
            auto bytesRead = socket->read(buffer, sizeof buffer);

            std::cout << "Received " << std::string(buffer, bytesRead) << std::endl;
        }
    }
}


int main()
{
    Reactor reactor;
    Listener listener(reactor);

    if (!listener.bind())
    {
        std::cout << "Failed to bind!\n";
        exit(1);
    }
    reactor.registerEvented(listener);

    std::cout << "Listening on 0.0.0.0:12345\n";
    reactor.run();
}