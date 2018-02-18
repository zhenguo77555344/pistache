/* epoll.h
   Mathieu Stefani, 18 February 2018
   
   Implementation of the Poller's interface based on linux epoll
*/

#pragma once

#include <pistache/io/poller.h>

namespace Pistache {
namespace Io {
namespace Polling {

class Epoll : public Poller {
public:
    Epoll(size_t max = 128);

    void addFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) override;
    void addFdOneShot(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) override;

    void removeFd(Fd fd) override;
    void rearmFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) override;

    int poll(std::vector<Event>& events,
             size_t maxEvents = Const::MaxEvents,
             std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) const override;

private:
    int toEpollEvents(Flags<NotifyOn> interest) const;
    Flags<NotifyOn> toNotifyOn(int events) const;
    int epoll_fd;
};

} // namespace Polling
} // namespace Io
} // namespace Pistache