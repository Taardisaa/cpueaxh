import ctypes
import os
import sys
import tempfile
import unittest

from cpueaxh import (
    CPUEAXH_ERR_ARG,
    CPUEAXH_ERR_HOOK,
    CPUEAXH_ERR_MODE,
    CPUEAXH_ESCAPE_INSN_CPUID,
    CPUEAXH_ESCAPE_INSN_SYSCALL,
    CPUEAXH_ESCAPE_INSN_XGETBV,
    CPUEAXH_HOOK_CODE_PRE,
    CPUEAXH_HOOK_MEM_READ_UNMAPPED,
    CPUEAXH_HOOK_MEM_WRITE_PROT,
    CPUEAXH_MEMORY_MODE_GUEST,
    CPUEAXH_MEMORY_MODE_HOST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RBX,
    CPUEAXH_X86_REG_RCX,
    CPUEAXH_X86_REG_RDX,
    CPUEAXH_X86_REG_RIP,
    CPUEAXH_X86_REG_RSP,
    CpueaxhError,
    Engine,
    HostBridgeSession,
    NativeBridgeLibrary,
    WindowsSyscallBufferSpec,
    WindowsSyscallSpec,
)
from cpueaxh._loader import default_library_path
from cpueaxh._loader import default_bridge_library_path
from cpueaxh.examples.ntreadfile_shellcode_demo import build_direct_ntreadfile_syscall_shellcode


class CpueaxhSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if sys.platform != "win32":
            raise unittest.SkipTest("cpueaxh Python smoke tests currently target Windows only")

        cls.dll_path = default_library_path()
        if not cls.dll_path.exists():
            raise unittest.SkipTest(
                f"cpueaxh_shared.dll was not found at the default locations; expected one near {cls.dll_path}"
            )
        cls.bridge_dll_path = default_bridge_library_path()

    def make_engine(self) -> Engine:
        return Engine(dll_path=str(self.dll_path))

    def make_bridge_library(self) -> NativeBridgeLibrary:
        return NativeBridgeLibrary(self.bridge_dll_path)

    def test_guest_execution_sets_rax(self) -> None:
        code_address = 0x1000
        code = bytes(
            [
                0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        )

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
            engine.write_register_u64(CPUEAXH_X86_REG_RIP, code_address)
            engine.start(code_address, count=1)
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RAX), 42)

    def test_code_hook_observes_each_instruction(self) -> None:
        code_address = 0x2000
        code = bytes(
            [
                0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x83, 0xC0, 0x01,
            ]
        )

        hits: list[int] = []

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
            engine.write_register_u64(CPUEAXH_X86_REG_RIP, code_address)
            hook = engine.add_code_hook(
                CPUEAXH_HOOK_CODE_PRE,
                lambda address: hits.append(address),
                code_address,
                code_address + len(code) - 1,
            )
            try:
                engine.start(code_address, count=2)
            finally:
                engine.delete_hook(hook)

            self.assertEqual(hits, [code_address, code_address + 10])
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RAX), 43)

    def test_map_host_buffer_exposes_python_bytearray(self) -> None:
        buffer_address = 0x3000
        backing = bytearray(0x1000)
        backing[:4] = b"TEST"

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.map_host_buffer(buffer_address, backing, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
            self.assertEqual(engine.read_memory(buffer_address, 4), b"TEST")
            engine.write_memory(buffer_address + 4, b"ING")

        self.assertEqual(backing[:7], b"TESTING")

    def test_set_processor_id_updates_context(self) -> None:
        with self.make_engine() as engine:
            engine.set_processor_id(7)
            context = engine.read_context()
            self.assertEqual(context.processor_id, 7)

    def test_memory_patch_overrides_host_reads_and_restores_after_delete(self) -> None:
        backing = ctypes.create_string_buffer(b"original\0")
        address = ctypes.addressof(backing)

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_HOST)
            self.assertEqual(engine.read_memory(address, 8), b"original")

            patch = engine.add_memory_patch(address, b"patched!")
            try:
                self.assertEqual(engine.read_memory(address, 8), b"patched!")
            finally:
                engine.delete_memory_patch(patch)

            self.assertEqual(engine.read_memory(address, 8), b"original")

    def test_invalid_memory_hooks_can_recover_execution(self) -> None:
        code_address = 0x120000
        stack_address = 0x220000
        source_address = 0x320000
        dest_address = 0x330000
        expected_source = 0x1122334455667788
        expected_result = expected_source + 5
        code = bytes(
            [
                0x48, 0xBB, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0xB9, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x8B, 0x03,
                0x48, 0x83, 0xC0, 0x05,
                0x48, 0x89, 0x01,
                0x90,
            ]
        )

        read_hits: list[int] = []
        write_hits: list[int] = []

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.map_memory(code_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
            engine.write_memory(code_address, code)
            engine.map_memory(stack_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
            engine.map_memory(dest_address, 0x1000, CPUEAXH_PROT_READ)
            engine.write_register_u64(CPUEAXH_X86_REG_RSP, stack_address + 0x1000 - 0x80)
            engine.write_register_u64(CPUEAXH_X86_REG_RIP, code_address)

            def recover_invalid_memory(kind: int, address: int, size: int, value: int) -> bool:
                self.assertGreater(size, 0)
                if kind == CPUEAXH_HOOK_MEM_READ_UNMAPPED:
                    read_hits.append(address)
                    engine.map_memory(source_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
                    engine.write_memory(source_address, expected_source.to_bytes(8, "little"))
                    return True
                if kind == CPUEAXH_HOOK_MEM_WRITE_PROT:
                    write_hits.append(address)
                    engine.protect_memory(dest_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
                    return True
                return False

            read_hook = engine.add_invalid_memory_hook(
                CPUEAXH_HOOK_MEM_READ_UNMAPPED,
                recover_invalid_memory,
                source_address,
                source_address + 0xFFF,
            )
            write_hook = engine.add_invalid_memory_hook(
                CPUEAXH_HOOK_MEM_WRITE_PROT,
                recover_invalid_memory,
                dest_address,
                dest_address + 0xFFF,
            )

            try:
                engine.start(code_address, code_address + len(code), count=0)
            finally:
                engine.delete_hook(read_hook)
                engine.delete_hook(write_hook)

            result = int.from_bytes(engine.read_memory(dest_address, 8), "little")
            self.assertEqual(result, expected_result)
            self.assertEqual(read_hits, [source_address])
            self.assertEqual(write_hits, [dest_address])

    def test_context_round_trip_preserves_richer_fields(self) -> None:
        with self.make_engine() as engine:
            context = engine.read_context()
            context.regs[0] = 0x1111111122222222
            context.regs[3] = 0x3333333344444444
            context.rip = 0x5555555566666666
            context.rflags = 0x202
            context.xmm[0].low = 0xAAAABBBBCCCCDDDD
            context.xmm[0].high = 0x1111222233334444
            context.ymm_upper[0].low = 0xDEADBEEFCAFEBABE
            context.ymm_upper[0].high = 0x0102030405060708
            context.mm[0] = 0x123456789ABCDEF0
            context.mxcsr = 0x1F80
            context.gs.selector = 0x2B
            context.gs.descriptor.base = 0x1000200030004000
            context.gs.descriptor.limit = 0xFFFF
            context.gs.descriptor.type = 3
            context.gs.descriptor.dpl = 3
            context.gs.descriptor.present = 1
            context.gs.descriptor.granularity = 1
            context.gs.descriptor.db = 1
            context.gs.descriptor.long_mode = 0
            context.control_regs[3] = 0xABCDEF000
            context.processor_id = 9

            engine.write_context(context)
            round_tripped = engine.read_context()

            self.assertEqual(round_tripped.regs[0], context.regs[0])
            self.assertEqual(round_tripped.regs[3], context.regs[3])
            self.assertEqual(round_tripped.rip, context.rip)
            self.assertEqual(round_tripped.rflags, context.rflags)
            self.assertEqual(round_tripped.xmm[0].low, context.xmm[0].low)
            self.assertEqual(round_tripped.xmm[0].high, context.xmm[0].high)
            self.assertEqual(round_tripped.ymm_upper[0].low, context.ymm_upper[0].low)
            self.assertEqual(round_tripped.ymm_upper[0].high, context.ymm_upper[0].high)
            self.assertEqual(round_tripped.mm[0], context.mm[0])
            self.assertEqual(round_tripped.mxcsr, context.mxcsr)
            self.assertEqual(round_tripped.gs.selector, context.gs.selector)
            self.assertEqual(round_tripped.gs.descriptor.base, context.gs.descriptor.base)
            self.assertEqual(round_tripped.gs.descriptor.limit, context.gs.descriptor.limit)
            self.assertEqual(round_tripped.gs.descriptor.type, context.gs.descriptor.type)
            self.assertEqual(round_tripped.gs.descriptor.dpl, context.gs.descriptor.dpl)
            self.assertEqual(round_tripped.gs.descriptor.present, context.gs.descriptor.present)
            self.assertEqual(round_tripped.gs.descriptor.granularity, context.gs.descriptor.granularity)
            self.assertEqual(round_tripped.gs.descriptor.db, context.gs.descriptor.db)
            self.assertEqual(round_tripped.gs.descriptor.long_mode, context.gs.descriptor.long_mode)
            self.assertEqual(round_tripped.control_regs[3], context.control_regs[3])
            self.assertEqual(round_tripped.processor_id, context.processor_id)

    def test_cpuid_escape_can_override_register_results(self) -> None:
        code_address = 0x5000
        code = bytes(
            [
                0xB8, 0x01, 0x00, 0x00, 0x00,
                0x31, 0xC9,
                0x0F, 0xA2,
            ]
        )

        leaves: list[tuple[int, int]] = []

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)

            def emulate_cpuid(context) -> None:
                leaves.append(
                    (
                        int(context.regs[CPUEAXH_X86_REG_RAX] & 0xFFFFFFFF),
                        int(context.regs[CPUEAXH_X86_REG_RCX] & 0xFFFFFFFF),
                    )
                )
                context.regs[CPUEAXH_X86_REG_RAX] = 0x12345678
                context.regs[CPUEAXH_X86_REG_RBX] = 0x87654321
                context.regs[CPUEAXH_X86_REG_RCX] = 0xAABBCCDD
                context.regs[CPUEAXH_X86_REG_RDX] = 0x0BADF00D

            escape = engine.add_escape(
                CPUEAXH_ESCAPE_INSN_CPUID,
                emulate_cpuid,
                code_address,
                code_address + len(code) - 1,
            )
            try:
                engine.start(code_address, count=3)
            finally:
                engine.delete_escape(escape)

            self.assertEqual(leaves, [(1, 0)])
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RAX), 0x12345678)
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RBX), 0x87654321)
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RCX), 0xAABBCCDD)
            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RDX), 0x0BADF00D)

    def test_start_function_returns_and_restores_original_stack_return(self) -> None:
        code_address = 0x4000
        stack_address = 0x8000
        stack_top = stack_address + 0x1000 - 0x100
        original_return = 0x1122334455667788
        code = bytes(
            [
                0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xC3,
            ]
        )

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
            engine.map_memory(stack_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE)
            engine.write_memory(stack_top, original_return.to_bytes(8, "little"))
            engine.write_register_u64(CPUEAXH_X86_REG_RSP, stack_top)

            engine.start_function(code_address, count=0)

            self.assertEqual(engine.read_register_u64(CPUEAXH_X86_REG_RAX), 0x1234)
            self.assertEqual(int.from_bytes(engine.read_memory(stack_top, 8), "little"), original_return)

    def test_invalid_arguments_raise_expected_error_codes(self) -> None:
        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)

            with self.assertRaises(CpueaxhError) as unaligned_map_error:
                engine.map_memory(0x1234, 0x100, CPUEAXH_PROT_READ)
            self.assertEqual(unaligned_map_error.exception.code, CPUEAXH_ERR_ARG)

            with self.assertRaises(CpueaxhError) as patch_mode_error:
                engine.add_memory_patch(0x1000, b"abcd")
            self.assertEqual(patch_mode_error.exception.code, CPUEAXH_ERR_MODE)

    def test_duplicate_escape_registration_raises_hook_error(self) -> None:
        code_address = 0x6000
        code = bytes([0x0F, 0xA2])

        with self.make_engine() as engine:
            engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
            engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
            first = engine.add_escape(CPUEAXH_ESCAPE_INSN_CPUID, lambda context: None)
            try:
                with self.assertRaises(CpueaxhError) as duplicate_error:
                    engine.add_escape(CPUEAXH_ESCAPE_INSN_CPUID, lambda context: None)
                self.assertEqual(duplicate_error.exception.code, CPUEAXH_ERR_HOOK)
            finally:
                engine.delete_escape(first)

    def test_host_call_can_invoke_native_cpuid_bridge(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        bridges = self.make_bridge_library()
        cpuid_bridge = bridges.symbol("cpueaxh_example_execute_cpuid")
        query_cpuid = bridges.function(
            "cpueaxh_example_query_cpuid",
            None,
            [
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
            ],
        )

        code = bytes(
            [
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0x31, 0xC9,
                0x0F, 0xA2,
            ]
        )
        expected_eax = ctypes.c_uint32()
        expected_ebx = ctypes.c_uint32()
        expected_ecx = ctypes.c_uint32()
        expected_edx = ctypes.c_uint32()
        query_cpuid(0, 0, expected_eax, expected_ebx, expected_ecx, expected_edx)

        with HostBridgeSession(dll_path=str(self.dll_path)) as session:
            _, code_address = session.load_code(code)
            escape = session.add_host_call_escape(
                CPUEAXH_ESCAPE_INSN_CPUID,
                cpuid_bridge,
                code_address,
                code_address + len(code) - 1,
            )
            try:
                session.start(code_address, count=3)
            finally:
                session.engine.delete_escape(escape)

            self.assertEqual(session.engine.read_register_u64(CPUEAXH_X86_REG_RAX) & 0xFFFFFFFF, expected_eax.value)
            self.assertEqual(session.engine.read_register_u64(CPUEAXH_X86_REG_RBX) & 0xFFFFFFFF, expected_ebx.value)
            self.assertEqual(session.engine.read_register_u64(CPUEAXH_X86_REG_RCX) & 0xFFFFFFFF, expected_ecx.value)
            self.assertEqual(session.engine.read_register_u64(CPUEAXH_X86_REG_RDX) & 0xFFFFFFFF, expected_edx.value)

    def test_host_call_can_invoke_native_xgetbv_bridge(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        bridges = self.make_bridge_library()
        cpuid_query = bridges.function(
            "cpueaxh_example_query_cpuid",
            None,
            [
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
            ],
        )
        eax = ctypes.c_uint32()
        ebx = ctypes.c_uint32()
        ecx = ctypes.c_uint32()
        edx = ctypes.c_uint32()
        cpuid_query(1, 0, eax, ebx, ecx, edx)
        if (ecx.value & (1 << 26)) == 0 or (ecx.value & (1 << 27)) == 0:
            self.skipTest("host CPU/OS does not report XSAVE+OSXSAVE support required for xgetbv")

        xgetbv_bridge = bridges.symbol("cpueaxh_example_execute_xgetbv")
        query_xgetbv = bridges.function(
            "cpueaxh_example_query_xgetbv",
            ctypes.c_uint64,
            [ctypes.c_uint32],
        )
        expected = int(query_xgetbv(0))
        code = bytes(
            [
                0x31, 0xC9,
                0x0F, 0x01, 0xD0,
            ]
        )

        with HostBridgeSession(dll_path=str(self.dll_path)) as session:
            _, code_address = session.load_code(code)
            escape = session.add_host_call_escape(
                CPUEAXH_ESCAPE_INSN_XGETBV,
                xgetbv_bridge,
                code_address,
                code_address + len(code) - 1,
            )
            try:
                session.start(code_address, count=2)
            finally:
                session.engine.delete_escape(escape)

            actual = (
                (session.engine.read_register_u64(CPUEAXH_X86_REG_RDX) & 0xFFFFFFFF) << 32
                | (session.engine.read_register_u64(CPUEAXH_X86_REG_RAX) & 0xFFFFFFFF)
            )
            self.assertEqual(actual, expected)

    def test_host_call_rejects_plain_context_without_escape_bridge_block(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        cpuid_bridge = self.make_bridge_library().symbol("cpueaxh_example_execute_cpuid")

        with self.make_engine() as engine:
            with self.assertRaises(CpueaxhError) as host_call_error:
                engine.host_call(engine.read_context(), cpuid_bridge)
            self.assertEqual(host_call_error.exception.code, CPUEAXH_ERR_ARG)

    def test_ntreadfile_syscall_bridge_reads_expected_bytes(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        payload = b"cpueaxh NtReadFile smoke"
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
            0x80000000,
            0x00000001,
            None,
            3,
            0x00000080,
            None,
        )
        if handle_value == ctypes.c_void_p(-1).value:
            self.fail("CreateFileW failed for NtReadFile smoke test")

        try:
            bridges = self.make_bridge_library()
            syscall_bridge = bridges.symbol("cpueaxh_example_execute_syscall")
            ntdll = NativeBridgeLibrary("ntdll.dll")
            nt_read_file = ntdll.symbol_address("NtReadFile")

            with HostBridgeSession(dll_path=str(self.dll_path)) as session:
                session.apply_windows_host_context(bridges)
                result = session.invoke_windows_syscall_spec(
                    WindowsSyscallSpec(
                        function_address=nt_read_file,
                        name="NtReadFile",
                        arguments=(
                            int(handle_value),
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

                self.assertEqual(result.status, 0)
                self.assertEqual(transferred, len(payload))
                self.assertEqual(content, payload)
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle_value))
            os.unlink(path)

    def test_direct_syscall_shellcode_reads_expected_bytes(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        payload = b"cpueaxh direct syscall smoke"
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
            0x80000000,
            0x00000001,
            None,
            3,
            0x00000080,
            None,
        )
        if handle_value == ctypes.c_void_p(-1).value:
            self.fail("CreateFileW failed for direct-syscall smoke test")

        try:
            bridges = self.make_bridge_library()
            syscall_bridge = bridges.symbol("cpueaxh_example_execute_syscall")
            ntdll = NativeBridgeLibrary("ntdll.dll")
            nt_read_file_syscall_number = ntdll.syscall_number("NtReadFile")

            with HostBridgeSession(dll_path=str(self.dll_path)) as session:
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

                self.assertEqual(status, 0)
                self.assertEqual(transferred, len(payload))
                self.assertEqual(content, payload)
                self.assertEqual(len(hits), 1)
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle_value))
            os.unlink(path)

    def test_invoke_windows_syscall_handles_register_only_arguments(self) -> None:
        if not self.bridge_dll_path.exists():
            self.skipTest(
                f"cpueaxh_native_bridges.dll was not found at the default locations; expected one near {self.bridge_dll_path}"
            )

        bridges = self.make_bridge_library()
        syscall_bridge = bridges.symbol("cpueaxh_example_execute_syscall")
        ntdll = NativeBridgeLibrary("ntdll.dll")
        nt_close = ntdll.symbol_address("NtClose")

        with HostBridgeSession(dll_path=str(self.dll_path)) as session:
            session.apply_windows_host_context(bridges)
            result = session.invoke_windows_syscall_spec(
                WindowsSyscallSpec(
                    function_address=nt_close,
                    name="NtClose",
                    arguments=(0,),
                ),
                syscall_bridge,
            )
            self.assertEqual(result.status, 0xC0000008)


if __name__ == "__main__":
    unittest.main()
