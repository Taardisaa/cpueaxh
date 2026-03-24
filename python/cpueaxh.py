from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_int, c_size_t, c_uint32, c_uint64, c_void_p
from pathlib import Path
from typing import Optional


CPUEAXH_ERR_OK = 0
CPUEAXH_ARCH_X86 = 1
CPUEAXH_MODE_64 = 8
CPUEAXH_MEMORY_MODE_GUEST = 0
CPUEAXH_MEMORY_MODE_HOST = 1
CPUEAXH_PROT_READ = 1
CPUEAXH_PROT_WRITE = 2
CPUEAXH_PROT_EXEC = 4
CPUEAXH_MEM_ATTR_USER = 1
CPUEAXH_X86_REG_RAX = 0
CPUEAXH_X86_REG_RCX = 1
CPUEAXH_X86_REG_RDX = 2
CPUEAXH_X86_REG_RBX = 3
CPUEAXH_X86_REG_RSP = 4
CPUEAXH_X86_REG_RBP = 5
CPUEAXH_X86_REG_RSI = 6
CPUEAXH_X86_REG_RDI = 7
CPUEAXH_X86_REG_R8 = 8
CPUEAXH_X86_REG_R9 = 9
CPUEAXH_X86_REG_R10 = 10
CPUEAXH_X86_REG_R11 = 11
CPUEAXH_X86_REG_R12 = 12
CPUEAXH_X86_REG_R13 = 13
CPUEAXH_X86_REG_R14 = 14
CPUEAXH_X86_REG_R15 = 15
CPUEAXH_X86_REG_RIP = 16
CPUEAXH_X86_REG_EFLAGS = 17


class CpueaxhError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{message} (cpueaxh_err={code})")
        self.code = code


class CpueaxhX86Xmm(ctypes.Structure):
    _fields_ = [
        ("low", c_uint64),
        ("high", c_uint64),
    ]


class CpueaxhX86SegmentDescriptor(ctypes.Structure):
    _fields_ = [
        ("base", c_uint64),
        ("limit", c_uint32),
        ("type", ctypes.c_uint8),
        ("dpl", ctypes.c_uint8),
        ("present", ctypes.c_uint8),
        ("granularity", ctypes.c_uint8),
        ("db", ctypes.c_uint8),
        ("long_mode", ctypes.c_uint8),
    ]


class CpueaxhX86Segment(ctypes.Structure):
    _fields_ = [
        ("selector", ctypes.c_uint16),
        ("reserved0", ctypes.c_uint16),
        ("descriptor", CpueaxhX86SegmentDescriptor),
    ]


class CpueaxhX86Context(ctypes.Structure):
    _fields_ = [
        ("regs", c_uint64 * 16),
        ("rip", c_uint64),
        ("rflags", c_uint64),
        ("xmm", CpueaxhX86Xmm * 16),
        ("ymm_upper", CpueaxhX86Xmm * 16),
        ("mm", c_uint64 * 8),
        ("mxcsr", c_uint32),
        ("reserved0", c_uint32),
        ("es", CpueaxhX86Segment),
        ("cs", CpueaxhX86Segment),
        ("ss", CpueaxhX86Segment),
        ("ds", CpueaxhX86Segment),
        ("fs", CpueaxhX86Segment),
        ("gs", CpueaxhX86Segment),
        ("gdtr_base", c_uint64),
        ("gdtr_limit", ctypes.c_uint16),
        ("reserved1", ctypes.c_uint16),
        ("ldtr_base", c_uint64),
        ("ldtr_limit", ctypes.c_uint16),
        ("reserved2", ctypes.c_uint16),
        ("cpl", ctypes.c_uint8),
        ("reserved3", ctypes.c_uint8 * 7),
        ("code_exception", c_uint32),
        ("error_code_exception", c_uint32),
        ("internal_bridge_block", c_uint64),
        ("control_regs", c_uint64 * 16),
        ("processor_id", c_uint32),
        ("reserved4", c_uint32),
    ]


class CpueaxhMemRegion(ctypes.Structure):
    _fields_ = [
        ("begin", c_uint64),
        ("end", c_uint64),
        ("perms", c_uint32),
        ("cpu_attrs", c_uint32),
    ]


def _default_library_path() -> Path:
    root = Path(__file__).resolve().parents[1]
    candidates = [
        root / "build" / "Debug" / "cpueaxh_shared.dll",
        root / "build" / "Release" / "cpueaxh_shared.dll",
        root / "build-cmake" / "Debug" / "cpueaxh_shared.dll",
        root / "build-cmake" / "Release" / "cpueaxh_shared.dll",
        root / "build-py" / "Debug" / "cpueaxh_shared.dll",
        root / "build-py" / "Release" / "cpueaxh_shared.dll",
        root / "x64" / "Debug" / "cpueaxh_shared.dll",
        root / "x64" / "Release" / "cpueaxh_shared.dll",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return root / "cpueaxh_shared.dll"


class _CpueaxhApi:
    def __init__(self, dll_path: Optional[str] = None) -> None:
        library_path = Path(dll_path) if dll_path else _default_library_path()
        self._dll = ctypes.WinDLL(str(library_path))
        self._bind()

    def _bind(self) -> None:
        self.cpueaxh_open = self._dll.cpueaxh_open
        self.cpueaxh_open.argtypes = [c_uint32, c_uint32, POINTER(c_void_p)]
        self.cpueaxh_open.restype = c_int

        self.cpueaxh_close = self._dll.cpueaxh_close
        self.cpueaxh_close.argtypes = [c_void_p]
        self.cpueaxh_close.restype = None

        self.cpueaxh_set_memory_mode = self._dll.cpueaxh_set_memory_mode
        self.cpueaxh_set_memory_mode.argtypes = [c_void_p, c_uint32]
        self.cpueaxh_set_memory_mode.restype = c_int

        self.cpueaxh_mem_map = self._dll.cpueaxh_mem_map
        self.cpueaxh_mem_map.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_map.restype = c_int

        self.cpueaxh_mem_unmap = self._dll.cpueaxh_mem_unmap
        self.cpueaxh_mem_unmap.argtypes = [c_void_p, c_uint64, c_size_t]
        self.cpueaxh_mem_unmap.restype = c_int

        self.cpueaxh_mem_protect = self._dll.cpueaxh_mem_protect
        self.cpueaxh_mem_protect.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_protect.restype = c_int

        self.cpueaxh_mem_set_cpu_attrs = self._dll.cpueaxh_mem_set_cpu_attrs
        self.cpueaxh_mem_set_cpu_attrs.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_set_cpu_attrs.restype = c_int

        self.cpueaxh_mem_write = self._dll.cpueaxh_mem_write
        self.cpueaxh_mem_write.argtypes = [c_void_p, c_uint64, c_void_p, c_size_t]
        self.cpueaxh_mem_write.restype = c_int

        self.cpueaxh_mem_read = self._dll.cpueaxh_mem_read
        self.cpueaxh_mem_read.argtypes = [c_void_p, c_uint64, c_void_p, c_size_t]
        self.cpueaxh_mem_read.restype = c_int

        self.cpueaxh_reg_write = self._dll.cpueaxh_reg_write
        self.cpueaxh_reg_write.argtypes = [c_void_p, c_int, c_void_p]
        self.cpueaxh_reg_write.restype = c_int

        self.cpueaxh_reg_read = self._dll.cpueaxh_reg_read
        self.cpueaxh_reg_read.argtypes = [c_void_p, c_int, c_void_p]
        self.cpueaxh_reg_read.restype = c_int

        self.cpueaxh_context_write = self._dll.cpueaxh_context_write
        self.cpueaxh_context_write.argtypes = [c_void_p, POINTER(CpueaxhX86Context)]
        self.cpueaxh_context_write.restype = c_int

        self.cpueaxh_context_read = self._dll.cpueaxh_context_read
        self.cpueaxh_context_read.argtypes = [c_void_p, POINTER(CpueaxhX86Context)]
        self.cpueaxh_context_read.restype = c_int

        self.cpueaxh_emu_start = self._dll.cpueaxh_emu_start
        self.cpueaxh_emu_start.argtypes = [c_void_p, c_uint64, c_uint64, c_uint64, c_size_t]
        self.cpueaxh_emu_start.restype = c_int

        self.cpueaxh_emu_start_function = self._dll.cpueaxh_emu_start_function
        self.cpueaxh_emu_start_function.argtypes = [c_void_p, c_uint64, c_uint64, c_size_t]
        self.cpueaxh_emu_start_function.restype = c_int

        self.cpueaxh_emu_stop = self._dll.cpueaxh_emu_stop
        self.cpueaxh_emu_stop.argtypes = [c_void_p]
        self.cpueaxh_emu_stop.restype = None

        self.cpueaxh_code_exception = self._dll.cpueaxh_code_exception
        self.cpueaxh_code_exception.argtypes = [c_void_p]
        self.cpueaxh_code_exception.restype = c_uint32

        self.cpueaxh_error_code_exception = self._dll.cpueaxh_error_code_exception
        self.cpueaxh_error_code_exception.argtypes = [c_void_p]
        self.cpueaxh_error_code_exception.restype = c_uint32

        self.cpueaxh_mem_regions = self._dll.cpueaxh_mem_regions
        self.cpueaxh_mem_regions.argtypes = [c_void_p, POINTER(POINTER(CpueaxhMemRegion)), POINTER(c_uint32)]
        self.cpueaxh_mem_regions.restype = c_int

        self.cpueaxh_free = self._dll.cpueaxh_free
        self.cpueaxh_free.argtypes = [c_void_p]
        self.cpueaxh_free.restype = None


class Engine:
    def __init__(self, dll_path: Optional[str] = None) -> None:
        self._api = _CpueaxhApi(dll_path)
        engine = c_void_p()
        self._check(self._api.cpueaxh_open(CPUEAXH_ARCH_X86, CPUEAXH_MODE_64, byref(engine)), "cpueaxh_open failed")
        self._engine = engine
        self._closed = False

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

    def mem_map(self, address: int, size: int, perms: int) -> None:
        self._check(self._api.cpueaxh_mem_map(self._engine, address, size, perms), "cpueaxh_mem_map failed")

    def mem_unmap(self, address: int, size: int) -> None:
        self._check(self._api.cpueaxh_mem_unmap(self._engine, address, size), "cpueaxh_mem_unmap failed")

    def mem_protect(self, address: int, size: int, perms: int) -> None:
        self._check(self._api.cpueaxh_mem_protect(self._engine, address, size, perms), "cpueaxh_mem_protect failed")

    def mem_set_cpu_attrs(self, address: int, size: int, attrs: int) -> None:
        self._check(self._api.cpueaxh_mem_set_cpu_attrs(self._engine, address, size, attrs), "cpueaxh_mem_set_cpu_attrs failed")

    def mem_write(self, address: int, data: bytes | bytearray | memoryview) -> None:
        payload = bytes(data)
        buffer = ctypes.create_string_buffer(payload)
        self._check(self._api.cpueaxh_mem_write(self._engine, address, ctypes.cast(buffer, c_void_p), len(payload)), "cpueaxh_mem_write failed")

    def mem_read(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        self._check(self._api.cpueaxh_mem_read(self._engine, address, ctypes.cast(buffer, c_void_p), size), "cpueaxh_mem_read failed")
        return buffer.raw

    def reg_write_u64(self, regid: int, value: int) -> None:
        raw = c_uint64(value)
        self._check(self._api.cpueaxh_reg_write(self._engine, regid, byref(raw)), "cpueaxh_reg_write failed")

    def reg_read_u64(self, regid: int) -> int:
        raw = c_uint64()
        self._check(self._api.cpueaxh_reg_read(self._engine, regid, byref(raw)), "cpueaxh_reg_read failed")
        return int(raw.value)

    def context_read(self) -> CpueaxhX86Context:
        context = CpueaxhX86Context()
        self._check(self._api.cpueaxh_context_read(self._engine, byref(context)), "cpueaxh_context_read failed")
        return context

    def context_write(self, context: CpueaxhX86Context) -> None:
        self._check(self._api.cpueaxh_context_write(self._engine, byref(context)), "cpueaxh_context_write failed")

    def emu_start(self, begin: int, until: int = 0, timeout: int = 0, count: int = 0) -> None:
        self._check(self._api.cpueaxh_emu_start(self._engine, begin, until, timeout, count), "cpueaxh_emu_start failed")

    def emu_start_function(self, begin: int, timeout: int = 0, count: int = 0) -> None:
        self._check(self._api.cpueaxh_emu_start_function(self._engine, begin, timeout, count), "cpueaxh_emu_start_function failed")

    def emu_stop(self) -> None:
        self._api.cpueaxh_emu_stop(self._engine)

    def code_exception(self) -> int:
        return int(self._api.cpueaxh_code_exception(self._engine))

    def error_code_exception(self) -> int:
        return int(self._api.cpueaxh_error_code_exception(self._engine))

    def mem_regions(self) -> list[CpueaxhMemRegion]:
        regions_ptr = POINTER(CpueaxhMemRegion)()
        count = c_uint32()
        self._check(self._api.cpueaxh_mem_regions(self._engine, byref(regions_ptr), byref(count)), "cpueaxh_mem_regions failed")
        try:
            return [regions_ptr[index] for index in range(count.value)]
        finally:
            if regions_ptr:
                self._api.cpueaxh_free(regions_ptr)
