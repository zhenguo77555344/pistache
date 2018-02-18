#pragma once

#include <pistache/io/poller.h>

namespace Pistache {
namespace Io {

class NotifyFd {
public:
    NotifyFd()
        : event_fd(-1)
    { }

    Polling::Tag bind(Polling::Poller& poller);

    bool isBound() const;

    Polling::Tag tag() const;

    void notify() const;

    void read() const;
    bool tryRead() const;

private:
    int event_fd;
};

} // namespace Io
} // namespace Pistache