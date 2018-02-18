/* os.cc
   Mathieu Stefani, 13 August 2015
   
*/

#include <fstream>
#include <iterator>
#include <algorithm>

#include <unistd.h>
#include <fcntl.h>

#include <pistache/os.h>
#include <pistache/common.h>

using namespace std;

namespace Pistache {

int hardware_concurrency() {
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo) {
        return std::count(std::istream_iterator<std::string>(cpuinfo),
                          std::istream_iterator<std::string>(),
                          std::string("processor"));
    }

    return sysconf(_SC_NPROCESSORS_ONLN);
}


bool make_non_blocking(int sfd)
{
    int flags = fcntl (sfd, F_GETFL, 0);
    if (flags == -1) return false; 

    flags |= O_NONBLOCK;
    int ret = fcntl (sfd, F_SETFL, flags);
    if (ret == -1) return false;

    return true;
}

CpuSet::CpuSet() {
    bits.reset();
}

CpuSet::CpuSet(std::initializer_list<size_t> cpus) {
    set(cpus);
}

void
CpuSet::clear() {
    bits.reset();
}

CpuSet&
CpuSet::set(size_t cpu) {
    if (cpu >= Size) {
        throw std::invalid_argument("Trying to set invalid cpu number");
    }

    bits.set(cpu);
    return *this;
}

CpuSet&
CpuSet::unset(size_t cpu) {
    if (cpu >= Size) {
        throw std::invalid_argument("Trying to unset invalid cpu number");
    }

    bits.set(cpu, false);
    return *this;
}

CpuSet&
CpuSet::set(std::initializer_list<size_t> cpus) {
    for (auto cpu: cpus) set(cpu);
    return *this;
}

CpuSet&
CpuSet::unset(std::initializer_list<size_t> cpus) {
    for (auto cpu: cpus) unset(cpu);
    return *this;
}

CpuSet&
CpuSet::setRange(size_t begin, size_t end) {
    if (begin > end) {
        throw std::range_error("Invalid range, begin > end");
    }

    for (size_t cpu = begin; cpu < end; ++cpu) {
        set(cpu);
    }

    return *this;
}

CpuSet&
CpuSet::unsetRange(size_t begin, size_t end) {
    if (begin > end) {
        throw std::range_error("Invalid range, begin > end");
    }

    for (size_t cpu = begin; cpu < end; ++cpu) {
        unset(cpu);
    }

    return *this;
}

bool
CpuSet::isSet(size_t cpu) const {
    if (cpu >= Size) {
        throw std::invalid_argument("Trying to test invalid cpu number");
    }

    return bits.test(cpu);
}

size_t
CpuSet::count() const {
    return bits.count();
}

cpu_set_t
CpuSet::toPosix() const {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    for (size_t cpu = 0; cpu < Size; ++cpu) {
        if (bits.test(cpu))
            CPU_SET(cpu, &cpu_set);
    }

    return cpu_set;
};

namespace Polling {




} // namespace Poller

} // namespace Pistache
