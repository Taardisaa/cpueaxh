from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_uint32, c_uint64, c_void_p
from dataclasses import dataclass
from os import PathLike

from ._bindings import CpueaxhApi
from ._constants import CPUEAXH_ARCH_X86, CPUEAXH_ERR_OK, CPUEAXH_MODE_64
from .errors import CpueaxhError
from .types import CpueaxhMemRegion, CpueaxhX86Context


@dataclass(frozen=True)
class MemoryRegion:
    begin: int
    end: int
    perms: int
    cpu_attrs: int

    @classmethod
    def from_ffi(cls, region: CpueaxhMemRegion) -> "MemoryRegion":
        return cls(
            begin=int(region.begin),
            end=int(region.end),
            perms=int(region.perms),
            cpu_attrs=int(region.cpu_attrs),
        )


class Engine:
    def __init__(self, dll_path: str | PathLike[str] | None = None) -> None:
        self._api = CpueaxhApi(dll_path)
        self._engine = c_void_p()
        self._closed = False
        self._check(
            self._api.cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, byref(self._engine)),
            "cpueaxh_open failed",
        )

    @property
    def dll_path(self) -> str:
        return str(self._api.path)

    def close(self) -> None:
        if not self._closed:
            self._api.cpueaxh_close(self._engine)
            self._closed = True

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _check(self, code: int, message: str) -> None:
        if code != CPUEAXH_ERR_OK:
            raise CpueaxhError(code, message)

    def set_memory_mode(self, mode: int) -> None:
        self._check(self._api.cpueaxh_set_memory_mode(self._engine, mode), "cpueaxh_set_memory_mode failed")

    def map_memory(self, address: int, size: int, perms: int) -> None:
        self._check(self._api.cpueaxh_mem_map(self._engine, address, size, perms), "cpueaxh_mem_map failed")

    def unmap_memory(self, address: int, size: int) -> None:
        self._check(self._api.cpueaxh_mem_unmap(self._engine, address, size), "cpueaxh_mem_unmap failed")

    def protect_memory(self, address: int, size: int, perms: int) -> None:
        self._check(self._api.cpueaxh_mem_protect(self._engine, address, size, perms), "cpueaxh_mem_protect failed")

    def set_memory_cpu_attrs(self, address: int, size: int, attrs: int) -> None:
        self._check(
            self._api.cpueaxh_mem_set_cpu_attrs(self._engine, address, size, attrs),
            "cpueaxh_mem_set_cpu_attrs failed",
        )

    def write_memory(self, address: int, data: bytes | bytearray | memoryview) -> None:
        payload = bytes(data)
        buffer = ctypes.create_string_buffer(payload)
        self._check(
            self._api.cpueaxh_mem_write(self._engine, address, ctypes.cast(buffer, c_void_p), len(payload)),
            "cpueaxh_mem_write failed",
        )

    def read_memory(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        self._check(
            self._api.cpueaxh_mem_read(self._engine, address, ctypes.cast(buffer, c_void_p), size),
            "cpueaxh_mem_read failed",
        )
        return buffer.raw

    def write_register_u64(self, regid: int, value: int) -> None:
        raw = c_uint64(value)
        self._check(self._api.cpueaxh_reg_write(self._engine, regid, byref(raw)), "cpueaxh_reg_write failed")

    def read_register_u64(self, regid: int) -> int:
        raw = c_uint64()
        self._check(self._api.cpueaxh_reg_read(self._engine, regid, byref(raw)), "cpueaxh_reg_read failed")
        return int(raw.value)

    def read_context(self) -> CpueaxhX86Context:
        context = CpueaxhX86Context()
        self._check(self._api.cpueaxh_context_read(self._engine, byref(context)), "cpueaxh_context_read failed")
        return context

    def write_context(self, context: CpueaxhX86Context) -> None:
        self._check(self._api.cpueaxh_context_write(self._engine, byref(context)), "cpueaxh_context_write failed")

    def start(self, begin: int, until: int = 0, timeout: int = 0, count: int = 0) -> None:
        self._check(
            self._api.cpueaxh_emu_start(self._engine, begin, until, timeout, count),
            "cpueaxh_emu_start failed",
        )

    def start_function(self, begin: int, timeout: int = 0, count: int = 0) -> None:
        self._check(
            self._api.cpueaxh_emu_start_function(self._engine, begin, timeout, count),
            "cpueaxh_emu_start_function failed",
        )

    def stop(self) -> None:
        self._api.cpueaxh_emu_stop(self._engine)

    def code_exception(self) -> int:
        return int(self._api.cpueaxh_code_exception(self._engine))

    def error_code_exception(self) -> int:
        return int(self._api.cpueaxh_error_code_exception(self._engine))

    def memory_regions(self) -> list[MemoryRegion]:
        regions_ptr = POINTER(CpueaxhMemRegion)()
        count = c_uint32()
        self._check(
            self._api.cpueaxh_mem_regions(self._engine, byref(regions_ptr), byref(count)),
            "cpueaxh_mem_regions failed",
        )
        try:
            return [MemoryRegion.from_ffi(regions_ptr[index]) for index in range(count.value)]
        finally:
            if regions_ptr:
                self._api.cpueaxh_free(regions_ptr)

    # Backward-compatible aliases for the earlier minimal glue.
    mem_map = map_memory
    mem_unmap = unmap_memory
    mem_protect = protect_memory
    mem_set_cpu_attrs = set_memory_cpu_attrs
    mem_write = write_memory
    mem_read = read_memory
    reg_write_u64 = write_register_u64
    reg_read_u64 = read_register_u64
    context_read = read_context
    context_write = write_context
    emu_start = start
    emu_start_function = start_function
    emu_stop = stop
    mem_regions = memory_regions
