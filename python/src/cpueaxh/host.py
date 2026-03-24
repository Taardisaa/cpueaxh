from __future__ import annotations

import ctypes
from dataclasses import dataclass
from os import PathLike

from ._constants import (
    CPUEAXH_MEMORY_MODE_HOST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RBP,
    CPUEAXH_X86_REG_RIP,
    CPUEAXH_X86_REG_RSP,
)
from ._loader import default_bridge_library_path
from .engine import Engine

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_SIZE = 0x1000
STACK_RED_ZONE = 0x80


def _page_align(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


@dataclass(slots=True)
class HostPage:
    address: int
    size: int
    buffer: ctypes.Array

    @classmethod
    def allocate(cls, size: int = PAGE_SIZE) -> "HostPage":
        kernel32 = ctypes.WinDLL("kernel32.dll")
        kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        aligned_size = _page_align(size)
        address = kernel32.VirtualAlloc(None, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not address:
            raise OSError("VirtualAlloc failed")
        buffer = (ctypes.c_ubyte * aligned_size).from_address(address)
        return cls(int(address), aligned_size, buffer)

    def write(self, data: bytes | bytearray | memoryview, offset: int = 0) -> int:
        payload = bytes(data)
        end = offset + len(payload)
        if offset < 0 or end > self.size:
            raise ValueError("payload does not fit in host page")
        ctypes.memmove(self.address + offset, payload, len(payload))
        return self.address + offset

    def top(self, red_zone: int = STACK_RED_ZONE) -> int:
        return self.address + self.size - red_zone

    def close(self) -> None:
        if self.address == 0:
            return
        kernel32 = ctypes.WinDLL("kernel32.dll")
        kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        kernel32.VirtualFree.restype = ctypes.c_int
        if not kernel32.VirtualFree(ctypes.c_void_p(self.address), 0, MEM_RELEASE):
            raise OSError("VirtualFree failed")
        self.address = 0
        self.size = 0

    def __enter__(self) -> "HostPage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class NativeBridgeLibrary:
    def __init__(self, path: str | PathLike[str] | None = None) -> None:
        self.path = str(path or default_bridge_library_path())
        self.dll = ctypes.WinDLL(self.path)

    def symbol(self, name: str):
        bridge = getattr(self.dll, name)
        bridge.restype = None
        return bridge

    def function(self, name: str, restype, argtypes: list[object]):
        func = getattr(self.dll, name)
        func.restype = restype
        func.argtypes = argtypes
        return func


class HostBridgeSession:
    def __init__(
        self,
        dll_path: str | PathLike[str] | None = None,
        stack_size: int = PAGE_SIZE,
        red_zone: int = STACK_RED_ZONE,
    ) -> None:
        self.engine = Engine(dll_path=dll_path)
        self.engine.set_memory_mode(CPUEAXH_MEMORY_MODE_HOST)
        self.red_zone = red_zone
        self._pages: list[HostPage] = []
        self._stack = self.allocate_page(stack_size)
        stack_top = self._stack.top(red_zone)
        self.engine.map_host_buffer(self._stack.address, self._stack.buffer, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
        self.engine.write_register_u64(CPUEAXH_X86_REG_RSP, stack_top)
        self.engine.write_register_u64(CPUEAXH_X86_REG_RBP, stack_top)

    @property
    def stack_address(self) -> int:
        return self._stack.address

    @property
    def stack_top(self) -> int:
        return self._stack.top(self.red_zone)

    def allocate_page(self, size: int = PAGE_SIZE) -> HostPage:
        page = HostPage.allocate(size)
        self._pages.append(page)
        return page

    def map_page(self, page: HostPage, perms: int) -> None:
        self.engine.map_host_buffer(page.address, page.buffer, perms)

    def load_code(self, code: bytes | bytearray | memoryview, perms: int = CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC) -> tuple[HostPage, int]:
        page = self.allocate_page(max(PAGE_SIZE, len(bytes(code))))
        address = page.write(code)
        self.map_page(page, perms)
        self.engine.write_register_u64(CPUEAXH_X86_REG_RIP, address)
        return page, address

    def add_host_call_escape(self, instruction_id: int, bridge, begin: int = 0, end: int = 0) -> int:
        def _callback(context) -> None:
            self.engine.host_call(context, bridge)

        return self.engine.add_escape(instruction_id, _callback, begin, end)

    def start(self, begin: int, until: int = 0, timeout: int = 0, count: int = 0) -> None:
        self.engine.start(begin, until, timeout, count)

    def close(self) -> None:
        page_errors: list[Exception] = []
        try:
            self.engine.close()
        finally:
            for page in reversed(self._pages):
                try:
                    page.close()
                except Exception as exc:
                    page_errors.append(exc)
            self._pages.clear()
        if page_errors:
            raise page_errors[0]

    def __enter__(self) -> "HostBridgeSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
