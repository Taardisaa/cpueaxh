from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_int, c_uint32, c_uint64, c_void_p
from dataclasses import dataclass
from os import PathLike
from typing import Callable

from ._bindings import CODE_HOOK_CALLBACK, ESCAPE_CALLBACK, INVALID_MEM_HOOK_CALLBACK, MEM_HOOK_CALLBACK, CpueaxhApi
from ._constants import CPUEAXH_ARCH_X86, CPUEAXH_ERR_ARG, CPUEAXH_ERR_OK, CPUEAXH_MODE_64
from .errors import CpueaxhError
from .types import CpueaxhMemRegion, CpueaxhX86Context

PAGE_SIZE = 0x1000


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


CodeHookCallback = Callable[[int], None]
MemoryHookCallback = Callable[[int, int, int, int], None]
InvalidMemoryHookCallback = Callable[[int, int, int, int], int | bool]
EscapeCallback = Callable[[CpueaxhX86Context], int | None]
HostBridge = object


class Engine:
    def __init__(self, dll_path: str | PathLike[str] | None = None) -> None:
        self._api = CpueaxhApi(dll_path)
        self._engine = c_void_p()
        self._closed = False
        self._mapped_buffers: dict[int, object] = {}
        self._hook_callbacks: dict[int, object] = {}
        self._escape_callbacks: dict[int, object] = {}
        self._patch_buffers: dict[int, object] = {}
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
            self._mapped_buffers.clear()
            self._hook_callbacks.clear()
            self._escape_callbacks.clear()
            self._patch_buffers.clear()
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

    def map_host_buffer(self, address: int, buffer: object, perms: int) -> None:
        if isinstance(buffer, bytearray):
            mapped = (ctypes.c_ubyte * len(buffer)).from_buffer(buffer)
            size = len(buffer)
        elif isinstance(buffer, memoryview):
            writable = buffer.cast("B")
            mapped = (ctypes.c_ubyte * len(writable)).from_buffer(writable)
            size = len(writable)
        elif isinstance(buffer, ctypes.Array):
            mapped = buffer
            size = ctypes.sizeof(buffer)
        else:
            raise TypeError("buffer must be a bytearray, writable memoryview, or ctypes array")

        self._check(
            self._api.cpueaxh_mem_map_ptr(self._engine, address, size, perms, ctypes.cast(mapped, c_void_p)),
            "cpueaxh_mem_map_ptr failed",
        )
        self._mapped_buffers[address] = (buffer, mapped)

    def unmap_memory(self, address: int, size: int) -> None:
        self._check(self._api.cpueaxh_mem_unmap(self._engine, address, size), "cpueaxh_mem_unmap failed")
        self._mapped_buffers.pop(address, None)

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

    def load_code(self, address: int, code: bytes | bytearray | memoryview, perms: int) -> None:
        payload = bytes(code)
        page_begin = address & ~(PAGE_SIZE - 1)
        page_end = (address + len(payload) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        self.map_memory(page_begin, page_end - page_begin, perms)
        self.write_memory(address, payload)

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

    def set_processor_id(self, processor_id: int) -> None:
        self._check(self._api.cpueaxh_set_processor_id(self._engine, processor_id), "cpueaxh_set_processor_id failed")

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

    def host_call(self, context: CpueaxhX86Context, bridge: HostBridge) -> None:
        bridge_ptr = self._as_bridge_pointer(bridge)
        self._check(self._api.cpueaxh_host_call(byref(context), bridge_ptr), "cpueaxh_host_call failed")

    def code_exception(self) -> int:
        return int(self._api.cpueaxh_code_exception(self._engine))

    def error_code_exception(self) -> int:
        return int(self._api.cpueaxh_error_code_exception(self._engine))

    def add_memory_patch(self, address: int, data: bytes | bytearray | memoryview) -> int:
        payload = bytes(data)
        buffer = ctypes.create_string_buffer(payload)
        handle = c_uint64()
        self._check(
            self._api.cpueaxh_mem_patch_add(
                self._engine,
                byref(handle),
                address,
                ctypes.cast(buffer, c_void_p),
                len(payload),
            ),
            "cpueaxh_mem_patch_add failed",
        )
        self._patch_buffers[int(handle.value)] = buffer
        return int(handle.value)

    def delete_memory_patch(self, handle: int) -> None:
        self._check(self._api.cpueaxh_mem_patch_del(self._engine, handle), "cpueaxh_mem_patch_del failed")
        self._patch_buffers.pop(handle, None)

    def add_code_hook(self, hook_type: int, callback: CodeHookCallback, begin: int = 0, end: int = 0) -> int:
        handle = c_uint64()

        def _callback(_engine_ptr: int, address: int, _user_data: int) -> None:
            callback(int(address))

        c_callback = CODE_HOOK_CALLBACK(_callback)
        self._check(
            self._api.cpueaxh_hook_add(
                self._engine,
                byref(handle),
                hook_type,
                ctypes.cast(c_callback, c_void_p),
                None,
                begin,
                end,
            ),
            "cpueaxh_hook_add failed",
        )
        self._hook_callbacks[int(handle.value)] = c_callback
        return int(handle.value)

    def add_code_hook_address(self, hook_type: int, callback: CodeHookCallback, address: int) -> int:
        handle = c_uint64()

        def _callback(_engine_ptr: int, current_address: int, _user_data: int) -> None:
            callback(int(current_address))

        c_callback = CODE_HOOK_CALLBACK(_callback)
        self._check(
            self._api.cpueaxh_hook_add_address(
                self._engine,
                byref(handle),
                hook_type,
                ctypes.cast(c_callback, c_void_p),
                None,
                address,
            ),
            "cpueaxh_hook_add_address failed",
        )
        self._hook_callbacks[int(handle.value)] = c_callback
        return int(handle.value)

    def add_memory_hook(self, hook_type: int, callback: MemoryHookCallback, begin: int = 0, end: int = 0) -> int:
        handle = c_uint64()

        def _callback(_engine_ptr: int, kind: int, address: int, size: int, value: int, _user_data: int) -> None:
            callback(int(kind), int(address), int(size), int(value))

        c_callback = MEM_HOOK_CALLBACK(_callback)
        self._check(
            self._api.cpueaxh_hook_add(
                self._engine,
                byref(handle),
                hook_type,
                ctypes.cast(c_callback, c_void_p),
                None,
                begin,
                end,
            ),
            "cpueaxh_hook_add failed",
        )
        self._hook_callbacks[int(handle.value)] = c_callback
        return int(handle.value)

    def add_invalid_memory_hook(
        self,
        hook_type: int,
        callback: InvalidMemoryHookCallback,
        begin: int = 0,
        end: int = 0,
    ) -> int:
        handle = c_uint64()

        def _callback(_engine_ptr: int, kind: int, address: int, size: int, value: int, _user_data: int) -> int:
            return int(bool(callback(int(kind), int(address), int(size), int(value))))

        c_callback = INVALID_MEM_HOOK_CALLBACK(_callback)
        self._check(
            self._api.cpueaxh_hook_add(
                self._engine,
                byref(handle),
                hook_type,
                ctypes.cast(c_callback, c_void_p),
                None,
                begin,
                end,
            ),
            "cpueaxh_hook_add failed",
        )
        self._hook_callbacks[int(handle.value)] = c_callback
        return int(handle.value)

    def delete_hook(self, handle: int) -> None:
        self._check(self._api.cpueaxh_hook_del(self._engine, handle), "cpueaxh_hook_del failed")
        self._hook_callbacks.pop(handle, None)
        self._escape_callbacks.pop(handle, None)

    def add_escape(self, instruction_id: int, callback: EscapeCallback, begin: int = 0, end: int = 0) -> int:
        handle = c_uint64()

        def _callback(_engine_ptr: int, context_ptr: POINTER(CpueaxhX86Context), _instruction_ptr: int, _user_data: int) -> int:
            result = callback(context_ptr.contents)
            if result is None:
                return CPUEAXH_ERR_OK
            if isinstance(result, bool):
                return CPUEAXH_ERR_OK if result else CPUEAXH_ERR_ARG
            return int(result)

        c_callback = ESCAPE_CALLBACK(_callback)
        self._check(
            self._api.cpueaxh_escape_add(
                self._engine,
                byref(handle),
                instruction_id,
                ctypes.cast(c_callback, c_void_p),
                None,
                begin,
                end,
            ),
            "cpueaxh_escape_add failed",
        )
        self._escape_callbacks[int(handle.value)] = c_callback
        return int(handle.value)

    def delete_escape(self, handle: int) -> None:
        self._check(self._api.cpueaxh_escape_del(self._engine, handle), "cpueaxh_escape_del failed")
        self._escape_callbacks.pop(handle, None)

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

    @staticmethod
    def _as_bridge_pointer(bridge: HostBridge) -> c_void_p:
        if isinstance(bridge, int):
            return c_void_p(bridge)
        if isinstance(bridge, c_void_p):
            return bridge
        try:
            return ctypes.cast(bridge, c_void_p)
        except (TypeError, ValueError) as exc:
            raise TypeError("bridge must be a function pointer, c_void_p, or integer address") from exc

    # Backward-compatible aliases for the earlier minimal glue.
    mem_map = map_memory
    mem_unmap = unmap_memory
    mem_protect = protect_memory
    mem_set_cpu_attrs = set_memory_cpu_attrs
    mem_write = write_memory
    mem_read = read_memory
    mem_map_ptr = map_host_buffer
    load_guest_code = load_code
    reg_write_u64 = write_register_u64
    reg_read_u64 = read_register_u64
    context_read = read_context
    context_write = write_context
    emu_start = start
    emu_start_function = start_function
    emu_stop = stop
    host_bridge_call = host_call
    mem_regions = memory_regions
    escape_add = add_escape
    escape_del = delete_escape
