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
#include <poll.h>
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
                     std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) = 0;
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
             std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) override
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

class Poll : public Poller
{
public:
    void registerFd(Fd fd, Tag tag, Flags<NotifyOn> interest) override
    {
        PollEntry entry(fd, tag);
        entry.events = toPollEvents(interest);
        fds.push_back(entry);
    }

    int poll(std::vector<Event>& events,
             size_t maxEvents = 1024,
             std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) override
    {
        pollfd* pollfds = fds.data();
        int ready_fds = -1;
        do {
            ready_fds = ::poll(pollfds, maxEvents, timeout.count());
        } while (ready_fds < 0 && errno == EINTR);

        if (ready_fds > 0) {
            for (int i = 0; i < ready_fds; ++i) {
                const struct pollfd *pfd = pollfds + i;
                const auto* entry = static_cast<const PollEntry *>(pfd);

                const Tag tag(entry->tag);

                Event event(tag);
                event.flags = toNotifyOn(entry->revents);
                events.push_back(event);
            }
        }

        return ready_fds;
    }

private:
    struct PollEntry : pollfd
    {
        PollEntry(Fd fd, Tag tag)
            : tag(tag)
        {
            this->fd = fd;
        }

        Tag tag;
    };

    static short toPollEvents(Flags<NotifyOn> interest)
    {
        short events = 0;

        if (interest.hasFlag(NotifyOn::Read))
            events |= POLLIN;
        if (interest.hasFlag(NotifyOn::Write))
            events |= POLLOUT;
        if (interest.hasFlag(NotifyOn::Hangup))
            events |= POLLHUP;
        if (interest.hasFlag(NotifyOn::Shutdown))
            events |= POLLRDHUP;

        return events;
    }

    static Flags<NotifyOn> toNotifyOn(int events)
    {
        Flags<NotifyOn> flags;

        if (events & POLLIN)
            flags.setFlag(NotifyOn::Read);
        if (events & POLLOUT)
            flags.setFlag(NotifyOn::Write);
        if (events & POLLHUP)
            flags.setFlag(NotifyOn::Hangup);
        if (events & POLLRDHUP) {
            flags.setFlag(NotifyOn::Shutdown);
        }

        return flags;
    }

    std::vector<PollEntry> fds;
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

class Listener;

template<typename T>
class Pool
{
public:

    static_assert(std::is_base_of<Evented, T>::value, "T must inherit from Evented");

    struct Key
    {
        friend class Pool<T>;

    private:
        Key(uint64_t value)
            : value(value)
        {
        }

        uint64_t value;
    };

    Pool(size_t start = 0, size_t capacity = 0)
        : start(start)
        , next(0)
    {
        reserve(capacity);
    }

    void reserve(size_t capacity)
    {
        if (capacity > 0)
            entries.reserve(capacity);
    }

    template<typename... Args>
    Key allocate(Args&& ...args)
    {
        auto index = next;
        auto key = makeKey(index);

        if (index == entries.size())
        {
            entries.emplace_back();
            auto& entry = entries.back();
            entry.construct(makeTag(key), std::forward<Args>(args)...);
            entry.state = State::Occupied;
            ++next;
        }
        else
        {
            auto& entry = entries[next];
            entry.construct(makeTag(key), std::forward<Args>(args)...);
            entry.state = State::Occupied;
        }

        return key;
    }

    void release(Key key)
    {
        auto index = getIndex(key);
        if (index >= entries.size())
            return;

        auto& entry = entries[index];
        if (entry.state == State::Occupied)
        {
            entry.destroy();
            next = index;
        }
    }

    T* get(Key key) const
    {
        auto index = getIndex(key);

        if (index >= entries.size())
            return nullptr;

        const auto& entry = entries[key.value - start];
        if (entry.state != State::Occupied)
            return nullptr;

        return entry.value();
    }

    T* get(uint64_t value) const
    {
        return get(Key(value));
    }
    
private:
    enum class State
    {
        Occupied,
        Free
    };

    struct Entry
    {
        using Storage = typename std::aligned_storage<sizeof(T), alignof(T)>::type;

        Storage storage;
        State state;

        template<typename... Args>
        void construct(Args&& ...args)
        {
            ::new (&storage) T(std::forward<Args>(args)...);
        }

        void destroy()
        {
            value()->~T();
            state = State::Free;
        }

        T* value() const
        {
            return reinterpret_cast<T *>(&const_cast<Entry *>(this)->storage);
        }
    };

    std::vector<Entry> entries;

    uint64_t getIndex(Key key) const
    {
        return key.value - start;
    }

    Key makeKey(uint64_t index) const
    {
        return Key(index + start);
    }

    static Poller::Tag makeTag(Key key)
    {
        return Poller::Tag(key.value);
    }

    uint64_t start;
    uint64_t next;
};

using SocketPool = Pool<Socket>;

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
    static constexpr size_t MaxSockets = 10000;

    Listener(Reactor& reactor)
        : Evented(Tag)
        , reactor(reactor)
        , transport(std::make_shared<Transport>(reactor, this))
        , socketPool(Tag.value() + 1, MaxSockets)
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

    Socket* accept()
    {
        struct sockaddr_in peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        int client_fd = ::accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (client_fd < 0) {
            throw std::runtime_error(strerror(errno));
        }

        make_non_blocking(client_fd);
        auto key = socketPool.allocate(client_fd);
        return socketPool.get(key);
    }


private:
    Reactor& reactor;

    std::shared_ptr<Transport> transport;
    Fd listen_fd;
    SocketPool socketPool;

    Socket* socket(Poller::Tag tag) const
    {
        return socketPool.get(tag.value());
    }
};

constexpr Poller::Tag Listener::Tag;

void Transport::handleEvent(std::vector<Poller::Event> events)
{
    for (const auto& event: events)
    {
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
    listener.bind();

    reactor.registerEvented(listener);

    reactor.run();
}
