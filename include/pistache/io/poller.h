/* io.h
   Mathieu Stefani, 18 February 2018
   
   Primitives for the underlying Pistache I/O subsystem
*/

#pragma once

#include <memory>
#include <chrono>
#include <vector>
#include <bitset>

#include <pistache/flags.h>
#include <pistache/common.h>
#include <pistache/os.h>

namespace Pistache {
namespace Io {
namespace Polling {

enum class Mode {
    Level,
    Edge
};

enum class NotifyOn {
    None = 0,

    Read     = 1,
    Write    = Read   << 1,
    Hangup   = Write  << 1,
    Shutdown = Hangup << 1
};

DECLARE_FLAGS_OPERATORS(NotifyOn);

struct Tag {
    friend class Epoll;

    explicit constexpr Tag(uint64_t value)
      : value_(value)
    { }

    constexpr uint64_t value() const { return value_; }

    friend constexpr bool operator==(Tag lhs, Tag rhs);

private:
    uint64_t value_;
};

inline constexpr bool operator==(Tag lhs, Tag rhs) {
    return lhs.value_ == rhs.value_;
}

struct Event {
    explicit Event(Tag tag) :
        tag(tag)
    { }

    Flags<NotifyOn> flags;
    Fd fd;
    Tag tag;
};

class Poller
{
    public:
        virtual ~Poller() = default;

        virtual void addFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) = 0;
        virtual void addFdOneShot(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) = 0;

        virtual void removeFd(Fd fd) = 0;
        virtual void rearmFd(Fd fd, Flags<NotifyOn> interest, Tag tag, Mode mode = Mode::Level) = 0;

        virtual int poll(std::vector<Event>& events,
                         size_t maxEvents = Const::MaxEvents,
                         std::chrono::milliseconds timeout = std::chrono::milliseconds(0)) const = 0;
};

} // namespace Polling
} // namespace Io
} // namespace Pistache