from __future__ import annotations

import ctypes
from dataclasses import dataclass
from os import PathLike

from ._constants import (
    CPUEAXH_ESCAPE_INSN_SYSCALL,
    CPUEAXH_MEMORY_MODE_HOST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_GS_BASE,
    CPUEAXH_X86_REG_GS_SELECTOR,
    CPUEAXH_X86_REG_RAX,
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
WINDOWS_X64_ARGUMENT_REGISTERS = (
    1,   # RCX
    2,   # RDX
    8,   # R8
    9,   # R9
)


def _page_align(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _extract_windows_x64_syscall_number(function_address: int) -> int:
    stub = ctypes.string_at(function_address, 32)
    pattern = b"\x4C\x8B\xD1\xB8"
    offset = stub.find(pattern)
    if offset < 0:
        raise ValueError("the target export does not look like a Windows x64 syscall stub")

    if b"\x0F\x05" not in stub[offset:]:
        raise ValueError("the target export does not contain a syscall instruction near the stub prologue")

    return int.from_bytes(stub[offset + 4:offset + 8], "little")


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

    def symbol_address(self, name: str) -> int:
        return int(ctypes.cast(getattr(self.dll, name), ctypes.c_void_p).value)

    def syscall_number(self, name: str) -> int:
        return _extract_windows_x64_syscall_number(self.symbol_address(name))

    def function(self, name: str, restype, argtypes: list[object]):
        func = getattr(self.dll, name)
        func.restype = restype
        func.argtypes = argtypes
        return func


@dataclass(slots=True)
class WindowsSyscallBufferSpec:
    size: int
    data: bytes | bytearray | memoryview = b""
    perms: int = CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE
    label: str | None = None

    def __post_init__(self) -> None:
        payload_size = len(bytes(self.data))
        self.size = max(int(self.size), payload_size)
        if self.size <= 0:
            raise ValueError("buffer spec size must be positive")


@dataclass(slots=True)
class WindowsSyscallBuffer:
    address: int
    size: int
    page: HostPage
    label: str | None = None

    def read(self, size: int | None = None, offset: int = 0) -> bytes:
        actual_size = self.size - offset if size is None else size
        if offset < 0 or actual_size < 0 or offset + actual_size > self.size:
            raise ValueError("requested range is outside the syscall buffer")
        return ctypes.string_at(self.address + offset, actual_size)

    def write(self, data: bytes | bytearray | memoryview, offset: int = 0) -> None:
        payload = bytes(data)
        if offset < 0 or offset + len(payload) > self.size:
            raise ValueError("payload does not fit in the syscall buffer")
        ctypes.memmove(self.address + offset, payload, len(payload))

    def read_u64(self, offset: int = 0) -> int:
        return int.from_bytes(self.read(8, offset), "little")


@dataclass(slots=True)
class WindowsSyscallSpec:
    function_address: int
    arguments: tuple[int | WindowsSyscallBufferSpec, ...]
    name: str | None = None


@dataclass(slots=True)
class WindowsSyscallResult:
    rax: int
    status: int
    arguments: tuple[int, ...]
    buffers_by_index: dict[int, WindowsSyscallBuffer]
    buffers_by_label: dict[str, WindowsSyscallBuffer]

    def buffer_at(self, argument_index: int) -> WindowsSyscallBuffer:
        if argument_index < 1:
            raise ValueError("argument indices are 1-based")
        return self.buffers_by_index[argument_index]

    def buffer(self, label: str) -> WindowsSyscallBuffer:
        return self.buffers_by_label[label]


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

    def apply_windows_host_context(self, bridges: NativeBridgeLibrary) -> None:
        query_gs_selector = bridges.function("cpueaxh_example_query_gs_selector", ctypes.c_uint16, [])
        query_teb = bridges.function("cpueaxh_example_query_teb", ctypes.c_uint64, [])
        self.engine.write_register_u64(CPUEAXH_X86_REG_GS_SELECTOR, int(query_gs_selector()))
        self.engine.write_register_u64(CPUEAXH_X86_REG_GS_BASE, int(query_teb()))

    def write_register_u64(self, regid: int, value: int) -> None:
        self.engine.write_register_u64(regid, value)

    def read_register_u64(self, regid: int) -> int:
        return self.engine.read_register_u64(regid)

    def write_memory(self, address: int, data: bytes | bytearray | memoryview) -> None:
        self.engine.write_memory(address, data)

    def read_memory(self, address: int, size: int) -> bytes:
        return self.engine.read_memory(address, size)

    def write_stack_qword(self, offset: int, value: int) -> None:
        self.engine.write_memory(self.stack_top + offset, int(value).to_bytes(8, "little", signed=False))

    def set_windows_x64_stack_argument(self, argument_index: int, value: int) -> None:
        if argument_index < 5:
            raise ValueError("stack arguments start at Windows x64 argument index 5")
        offset = 0x28 + (argument_index - 5) * 8
        self.write_stack_qword(offset, value)

    def set_windows_x64_arguments(self, arguments: list[int] | tuple[int, ...]) -> None:
        for regid in WINDOWS_X64_ARGUMENT_REGISTERS:
            self.write_register_u64(regid, 0)

        for index, value in enumerate(arguments, start=1):
            if index <= len(WINDOWS_X64_ARGUMENT_REGISTERS):
                self.write_register_u64(WINDOWS_X64_ARGUMENT_REGISTERS[index - 1], value)
            else:
                self.set_windows_x64_stack_argument(index, value)

    def prepare_windows_x64_call(self, function_address: int, arguments: list[int] | tuple[int, ...]) -> None:
        self.set_windows_x64_arguments(arguments)
        self.write_register_u64(CPUEAXH_X86_REG_RIP, function_address)

    def create_syscall_buffer(self, spec: WindowsSyscallBufferSpec) -> WindowsSyscallBuffer:
        page = self.allocate_page(max(PAGE_SIZE, spec.size))
        self.map_page(page, spec.perms)
        buffer = WindowsSyscallBuffer(
            address=page.address,
            size=spec.size,
            page=page,
            label=spec.label,
        )
        if spec.data:
            buffer.write(spec.data)
        return buffer

    def invoke_windows_syscall_spec(
        self,
        spec: WindowsSyscallSpec,
        syscall_bridge,
        timeout: int = 0,
        count: int = 0,
    ) -> WindowsSyscallResult:
        resolved_arguments: list[int] = []
        buffers_by_index: dict[int, WindowsSyscallBuffer] = {}
        buffers_by_label: dict[str, WindowsSyscallBuffer] = {}

        for argument_index, argument in enumerate(spec.arguments, start=1):
            if isinstance(argument, WindowsSyscallBufferSpec):
                buffer = self.create_syscall_buffer(argument)
                resolved_arguments.append(buffer.address)
                buffers_by_index[argument_index] = buffer
                if buffer.label:
                    buffers_by_label[buffer.label] = buffer
            else:
                resolved_arguments.append(int(argument))

        rax = self.invoke_windows_syscall(
            spec.function_address,
            syscall_bridge,
            tuple(resolved_arguments),
            timeout=timeout,
            count=count,
        )
        return WindowsSyscallResult(
            rax=rax,
            status=rax & 0xFFFFFFFF,
            arguments=tuple(resolved_arguments),
            buffers_by_index=buffers_by_index,
            buffers_by_label=buffers_by_label,
        )

    def invoke_windows_syscall(
        self,
        syscall_address: int,
        syscall_bridge,
        arguments: list[int] | tuple[int, ...],
        timeout: int = 0,
        count: int = 0,
    ) -> int:
        self.prepare_windows_x64_call(syscall_address, arguments)
        escape = self.add_host_call_escape(CPUEAXH_ESCAPE_INSN_SYSCALL, syscall_bridge)
        try:
            self.start_function(0, timeout=timeout, count=count)
        finally:
            self.engine.delete_escape(escape)
        return self.read_register_u64(CPUEAXH_X86_REG_RAX)

    def start(self, begin: int, until: int = 0, timeout: int = 0, count: int = 0) -> None:
        self.engine.start(begin, until, timeout, count)

    def start_function(self, begin: int = 0, timeout: int = 0, count: int = 0) -> None:
        self.engine.start_function(begin, timeout, count)

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
