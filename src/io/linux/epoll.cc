/* epoll.cc
   Mathieu Stefani, 18 February 2018
   
*/

#include <sys/epoll.h>

#include <pistache/io/epoll.h>

namespace Pistache {
namespace Io {
namespace Polling {

    Epoll::Epoll(size_t max) {
        epoll_fd = TRY_RET(epoll_create(max));
    }

    void
    Epoll::addFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode) {
        struct epoll_event ev;
        ev.events = toEpollEvents(interest);
        if (mode == Mode::Edge)
            ev.events |= EPOLLET;
        ev.data.u64 = tag.value_;

        TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev));
    }

    void
    Epoll::addFdOneShot(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode) {
        struct epoll_event ev;
        ev.events = toEpollEvents(interest);
        ev.events |= EPOLLONESHOT;
        if (mode == Mode::Edge)
            ev.events |= EPOLLET;
        ev.data.u64 = tag.value_;

        TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev));
    }

    void
    Epoll::removeFd(Fd fd) {
        struct epoll_event ev;
        TRY(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev));
    }

    void
    Epoll::rearmFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode) {
        struct epoll_event ev;
        ev.events = toEpollEvents(interest);
        if (mode == Mode::Edge)
            ev.events |= EPOLLET;
        ev.data.u64 = tag.value_;

        TRY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev));
    }

    int
    Epoll::poll(std::vector<Event>& events, size_t maxEvents, std::chrono::milliseconds timeout) const {
        struct epoll_event evs[Const::MaxEvents];

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

    int
    Epoll::toEpollEvents(Flags<NotifyOn> interest) const {
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

    Flags<NotifyOn>
    Epoll::toNotifyOn(int events) const {
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

} // namespace Polling
} // namespace Io
} // namespace Pistache