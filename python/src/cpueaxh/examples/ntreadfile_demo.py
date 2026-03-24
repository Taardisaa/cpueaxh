import ctypes
import os
import tempfile

from cpueaxh import (
    HostBridgeSession,
    NativeBridgeLibrary,
    WindowsSyscallBufferSpec,
    WindowsSyscallSpec,
)

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def main() -> None:
    payload = b"cpueaxh NtReadFile demo"
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

    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError("CreateFileW failed")

    try:
        bridges = NativeBridgeLibrary()
        syscall_bridge = bridges.symbol("cpueaxh_example_execute_syscall")
        ntdll = NativeBridgeLibrary("ntdll.dll")
        nt_read_file = ntdll.symbol_address("NtReadFile")

        with HostBridgeSession() as session:
            session.apply_windows_host_context(bridges)
            result = session.invoke_windows_syscall_spec(
                WindowsSyscallSpec(
                    function_address=nt_read_file,
                    name="NtReadFile",
                    arguments=(
                        int(handle),
                        0,
                        0,
                        0,
                        WindowsSyscallBufferSpec(16, label="io_status"),
                        WindowsSyscallBufferSpec(len(payload), label="buffer"),
                        len(payload),
                        0,
                        0,
                    ),
                ),
                syscall_bridge,
            )
            transferred = result.buffer("io_status").read_u64(8)
            content = result.buffer("buffer").read()
            print(f"NTSTATUS = 0x{result.status:08X}")
            print(f"BYTES = {transferred}")
            print(content.decode('ascii'))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        os.unlink(path)


if __name__ == "__main__":
    main()
