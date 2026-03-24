import ctypes
import os
import struct
import tempfile

from cpueaxh import (
    CPUEAXH_ESCAPE_INSN_SYSCALL,
    CPUEAXH_X86_REG_RAX,
    HostBridgeSession,
    NativeBridgeLibrary,
    WindowsSyscallBufferSpec,
)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def build_direct_ntreadfile_syscall_shellcode(
    handle_value: int,
    io_status_address: int,
    buffer_address: int,
    buffer_length: int,
    syscall_number: int,
) -> bytes:
    code = bytearray()

    def mov_imm64_to_rax(value: int) -> None:
        code.extend(b"\x48\xB8")
        code.extend(struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    code.extend(b"\x48\xB9")
    code.extend(struct.pack("<Q", handle_value & 0xFFFFFFFFFFFFFFFF))
    code.extend(b"\x31\xD2")           # xor edx, edx
    code.extend(b"\x45\x31\xC0")       # xor r8d, r8d
    code.extend(b"\x45\x31\xC9")       # xor r9d, r9d

    mov_imm64_to_rax(io_status_address)
    code.extend(b"\x48\x89\x44\x24\x28")

    mov_imm64_to_rax(buffer_address)
    code.extend(b"\x48\x89\x44\x24\x30")

    mov_imm64_to_rax(buffer_length)
    code.extend(b"\x48\x89\x44\x24\x38")

    code.extend(b"\x31\xC0")           # xor eax, eax
    code.extend(b"\x48\x89\x44\x24\x40")
    code.extend(b"\x48\x89\x44\x24\x48")

    code.extend(b"\x4C\x8B\xD1")       # mov r10, rcx
    code.extend(b"\xB8")
    code.extend(struct.pack("<I", syscall_number & 0xFFFFFFFF))
    code.extend(b"\x0F\x05")           # syscall
    code.extend(b"\xC3")               # ret
    return bytes(code)


def main() -> None:
    payload = b"cpueaxh direct-syscall NtReadFile demo"
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(payload)
        path = handle.name

    kernel32 = ctypes.WinDLL("kernel32.dll")
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle_value = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle_value == INVALID_HANDLE_VALUE:
        raise OSError("CreateFileW failed")

    try:
        bridges = NativeBridgeLibrary()
        syscall_bridge = bridges.symbol("cpueaxh_example_execute_syscall")
        ntdll = NativeBridgeLibrary("ntdll.dll")
        nt_read_file_syscall_number = ntdll.syscall_number("NtReadFile")

        with HostBridgeSession() as session:
            session.apply_windows_host_context(bridges)
            io_status = session.create_syscall_buffer(WindowsSyscallBufferSpec(16, label="io_status"))
            output = session.create_syscall_buffer(WindowsSyscallBufferSpec(len(payload), label="buffer"))

            shellcode = build_direct_ntreadfile_syscall_shellcode(
                int(handle_value),
                io_status.address,
                output.address,
                len(payload),
                nt_read_file_syscall_number,
            )
            _, shellcode_address = session.load_code(shellcode)

            hits: list[int] = []

            def on_syscall(context) -> None:
                hits.append(int(context.rip))
                session.engine.host_call(context, syscall_bridge)

            escape = session.engine.add_escape(CPUEAXH_ESCAPE_INSN_SYSCALL, on_syscall)
            try:
                session.start_function(shellcode_address, count=0)
            finally:
                session.engine.delete_escape(escape)

            transferred = io_status.read_u64(8)
            content = output.read()
            status = session.read_register_u64(CPUEAXH_X86_REG_RAX) & 0xFFFFFFFF
            print(f"SYSCALL = 0x{nt_read_file_syscall_number:04X}")
            print(f"ESCAPES = {len(hits)}")
            print(f"NTSTATUS = 0x{status:08X}")
            print(f"BYTES = {transferred}")
            print(content.decode("ascii"))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle_value))
        os.unlink(path)


if __name__ == "__main__":
    main()
