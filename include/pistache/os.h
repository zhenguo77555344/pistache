/* os.h
   Mathieu Stefani, 13 August 2015
   
   Operating system specific functions
*/

#pragma once

#include <memory>
#include <chrono>
#include <vector>
#include <bitset>

#include <sched.h>

#include <pistache/flags.h>
#include <pistache/common.h>

namespace Pistache {

// @Todo @Correctness strong-typing using a struct
using Fd = int;

int hardware_concurrency();
bool make_non_blocking(int fd);

class CpuSet {
public:
    static constexpr size_t Size = 1024;

    CpuSet();
    explicit CpuSet(std::initializer_list<size_t> cpus);

    void clear();
    CpuSet& set(size_t cpu);
    CpuSet& unset(size_t cpu);

    CpuSet& set(std::initializer_list<size_t> cpus);
    CpuSet& unset(std::initializer_list<size_t> cpus);

    CpuSet& setRange(size_t begin, size_t end);
    CpuSet& unsetRange(size_t begin, size_t end);

    bool isSet(size_t cpu) const;
    size_t count() const;

    cpu_set_t toPosix() const;

private:
    std::bitset<Size> bits;
};


} // namespace Pistache
