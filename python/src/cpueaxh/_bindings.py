import ctypes
import os
from ctypes import POINTER, c_int, c_size_t, c_uint32, c_uint64, c_void_p
from pathlib import Path

from ._loader import default_library_path
from .types import CpueaxhMemRegion, CpueaxhX86Context

CODE_HOOK_CALLBACK = ctypes.CFUNCTYPE(None, c_void_p, c_uint64, c_void_p)
MEM_HOOK_CALLBACK = ctypes.CFUNCTYPE(None, c_void_p, c_uint32, c_uint64, c_size_t, c_uint64, c_void_p)
INVALID_MEM_HOOK_CALLBACK = ctypes.CFUNCTYPE(c_int, c_void_p, c_uint32, c_uint64, c_size_t, c_uint64, c_void_p)
ESCAPE_CALLBACK = ctypes.CFUNCTYPE(c_int, c_void_p, POINTER(CpueaxhX86Context), c_void_p, c_void_p)


class CpueaxhApi:
    def __init__(self, dll_path: str | os.PathLike[str] | None = None) -> None:
        library_path = Path(dll_path) if dll_path else default_library_path()
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(library_path.parent))
        self.path = library_path
        self.dll = ctypes.WinDLL(str(library_path))
        self._bind()

    def _bind(self) -> None:
        self.cpueaxh_open = self.dll.cpueaxh_open
        self.cpueaxh_open.argtypes = [c_uint32, c_uint32, POINTER(c_void_p)]
        self.cpueaxh_open.restype = c_int

        self.cpueaxh_close = self.dll.cpueaxh_close
        self.cpueaxh_close.argtypes = [c_void_p]
        self.cpueaxh_close.restype = None

        self.cpueaxh_set_memory_mode = self.dll.cpueaxh_set_memory_mode
        self.cpueaxh_set_memory_mode.argtypes = [c_void_p, c_uint32]
        self.cpueaxh_set_memory_mode.restype = c_int

        self.cpueaxh_mem_map = self.dll.cpueaxh_mem_map
        self.cpueaxh_mem_map.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_map.restype = c_int

        self.cpueaxh_mem_map_ptr = self.dll.cpueaxh_mem_map_ptr
        self.cpueaxh_mem_map_ptr.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32, c_void_p]
        self.cpueaxh_mem_map_ptr.restype = c_int

        self.cpueaxh_mem_unmap = self.dll.cpueaxh_mem_unmap
        self.cpueaxh_mem_unmap.argtypes = [c_void_p, c_uint64, c_size_t]
        self.cpueaxh_mem_unmap.restype = c_int

        self.cpueaxh_mem_protect = self.dll.cpueaxh_mem_protect
        self.cpueaxh_mem_protect.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_protect.restype = c_int

        self.cpueaxh_mem_set_cpu_attrs = self.dll.cpueaxh_mem_set_cpu_attrs
        self.cpueaxh_mem_set_cpu_attrs.argtypes = [c_void_p, c_uint64, c_size_t, c_uint32]
        self.cpueaxh_mem_set_cpu_attrs.restype = c_int

        self.cpueaxh_mem_write = self.dll.cpueaxh_mem_write
        self.cpueaxh_mem_write.argtypes = [c_void_p, c_uint64, c_void_p, c_size_t]
        self.cpueaxh_mem_write.restype = c_int

        self.cpueaxh_mem_read = self.dll.cpueaxh_mem_read
        self.cpueaxh_mem_read.argtypes = [c_void_p, c_uint64, c_void_p, c_size_t]
        self.cpueaxh_mem_read.restype = c_int

        self.cpueaxh_reg_write = self.dll.cpueaxh_reg_write
        self.cpueaxh_reg_write.argtypes = [c_void_p, c_int, c_void_p]
        self.cpueaxh_reg_write.restype = c_int

        self.cpueaxh_reg_read = self.dll.cpueaxh_reg_read
        self.cpueaxh_reg_read.argtypes = [c_void_p, c_int, c_void_p]
        self.cpueaxh_reg_read.restype = c_int

        self.cpueaxh_set_processor_id = self.dll.cpueaxh_set_processor_id
        self.cpueaxh_set_processor_id.argtypes = [c_void_p, c_uint32]
        self.cpueaxh_set_processor_id.restype = c_int

        self.cpueaxh_context_write = self.dll.cpueaxh_context_write
        self.cpueaxh_context_write.argtypes = [c_void_p, POINTER(CpueaxhX86Context)]
        self.cpueaxh_context_write.restype = c_int

        self.cpueaxh_context_read = self.dll.cpueaxh_context_read
        self.cpueaxh_context_read.argtypes = [c_void_p, POINTER(CpueaxhX86Context)]
        self.cpueaxh_context_read.restype = c_int

        self.cpueaxh_emu_start = self.dll.cpueaxh_emu_start
        self.cpueaxh_emu_start.argtypes = [c_void_p, c_uint64, c_uint64, c_uint64, c_size_t]
        self.cpueaxh_emu_start.restype = c_int

        self.cpueaxh_emu_start_function = self.dll.cpueaxh_emu_start_function
        self.cpueaxh_emu_start_function.argtypes = [c_void_p, c_uint64, c_uint64, c_size_t]
        self.cpueaxh_emu_start_function.restype = c_int

        self.cpueaxh_emu_stop = self.dll.cpueaxh_emu_stop
        self.cpueaxh_emu_stop.argtypes = [c_void_p]
        self.cpueaxh_emu_stop.restype = None

        self.cpueaxh_code_exception = self.dll.cpueaxh_code_exception
        self.cpueaxh_code_exception.argtypes = [c_void_p]
        self.cpueaxh_code_exception.restype = c_uint32

        self.cpueaxh_error_code_exception = self.dll.cpueaxh_error_code_exception
        self.cpueaxh_error_code_exception.argtypes = [c_void_p]
        self.cpueaxh_error_code_exception.restype = c_uint32

        self.cpueaxh_mem_regions = self.dll.cpueaxh_mem_regions
        self.cpueaxh_mem_regions.argtypes = [c_void_p, POINTER(POINTER(CpueaxhMemRegion)), POINTER(c_uint32)]
        self.cpueaxh_mem_regions.restype = c_int

        self.cpueaxh_mem_patch_add = self.dll.cpueaxh_mem_patch_add
        self.cpueaxh_mem_patch_add.argtypes = [c_void_p, POINTER(c_uint64), c_uint64, c_void_p, c_size_t]
        self.cpueaxh_mem_patch_add.restype = c_int

        self.cpueaxh_mem_patch_del = self.dll.cpueaxh_mem_patch_del
        self.cpueaxh_mem_patch_del.argtypes = [c_void_p, c_uint64]
        self.cpueaxh_mem_patch_del.restype = c_int

        self.cpueaxh_hook_add = self.dll.cpueaxh_hook_add
        self.cpueaxh_hook_add.argtypes = [c_void_p, POINTER(c_uint64), c_uint32, c_void_p, c_void_p, c_uint64, c_uint64]
        self.cpueaxh_hook_add.restype = c_int

        self.cpueaxh_hook_add_address = self.dll.cpueaxh_hook_add_address
        self.cpueaxh_hook_add_address.argtypes = [c_void_p, POINTER(c_uint64), c_uint32, c_void_p, c_void_p, c_uint64]
        self.cpueaxh_hook_add_address.restype = c_int

        self.cpueaxh_hook_del = self.dll.cpueaxh_hook_del
        self.cpueaxh_hook_del.argtypes = [c_void_p, c_uint64]
        self.cpueaxh_hook_del.restype = c_int

        self.cpueaxh_escape_add = self.dll.cpueaxh_escape_add
        self.cpueaxh_escape_add.argtypes = [c_void_p, POINTER(c_uint64), c_uint32, c_void_p, c_void_p, c_uint64, c_uint64]
        self.cpueaxh_escape_add.restype = c_int

        self.cpueaxh_escape_del = self.dll.cpueaxh_escape_del
        self.cpueaxh_escape_del.argtypes = [c_void_p, c_uint64]
        self.cpueaxh_escape_del.restype = c_int

        self.cpueaxh_free = self.dll.cpueaxh_free
        self.cpueaxh_free.argtypes = [c_void_p]
        self.cpueaxh_free.restype = None
