/* notify.cc
   Mathieu Stefani, 18 February 2018
   
*/

#include <sys/eventfd.h>

#include <pistache/io/notify_fd.h>

namespace Pistache {
namespace Io {

Polling::Tag
NotifyFd::bind(Polling::Poller& poller) {
    event_fd = TRY_RET(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    Polling::Tag tag(event_fd);

    poller.addFd(event_fd, Polling::NotifyOn::Read, tag, Polling::Mode::Edge);
    return tag;
}

bool
NotifyFd::isBound() const {
    return event_fd != -1;
}

Polling::Tag
NotifyFd::tag() const {
    return Polling::Tag(event_fd);
}

void
NotifyFd::notify() const {
    if (!isBound())
        throw std::runtime_error("Can not notify an unbound fd");
    eventfd_t val = 1;
    TRY(eventfd_write(event_fd, val));
}

void
NotifyFd::read() const {
    if (!isBound())
        throw std::runtime_error("Can not read an unbound fd");
    eventfd_t val;
    TRY(eventfd_read(event_fd, &val));
}

bool
NotifyFd::tryRead() const {
    eventfd_t val;
    int res = eventfd_read(event_fd, &val);
    if (res == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return false;
        throw std::runtime_error("Failed to read eventfd");
    }

    return true;
}

} // namespace Io
} // namespace Pistache