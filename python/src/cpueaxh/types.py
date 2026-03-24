import ctypes
from ctypes import c_uint16, c_uint32, c_uint64


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
        ("selector", c_uint16),
        ("reserved0", c_uint16),
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
        ("gdtr_limit", c_uint16),
        ("reserved1", c_uint16),
        ("ldtr_base", c_uint64),
        ("ldtr_limit", c_uint16),
        ("reserved2", c_uint16),
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
