#include <intrin.h>
#include <stdint.h>

extern "C" __declspec(dllexport) void cpueaxh_example_query_cpuid(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t* eax,
    uint32_t* ebx,
    uint32_t* ecx,
    uint32_t* edx) {
    int regs[4] = {};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    if (eax) *eax = static_cast<uint32_t>(regs[0]);
    if (ebx) *ebx = static_cast<uint32_t>(regs[1]);
    if (ecx) *ecx = static_cast<uint32_t>(regs[2]);
    if (edx) *edx = static_cast<uint32_t>(regs[3]);
}

extern "C" __declspec(dllexport) unsigned __int64 cpueaxh_example_query_xgetbv(uint32_t index) {
    return static_cast<unsigned __int64>(_xgetbv(index));
}
