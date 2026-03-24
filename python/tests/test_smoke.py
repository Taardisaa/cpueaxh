import ctypes
import sys
import unittest

from cpueaxh import (
    CPUEAXH_ERR_ARG,
    CPUEAXH_ERR_MODE,
    CPUEAXH_HOOK_CODE_PRE,
    CPUEAXH_HOOK_MEM_READ_UNMAPPED,
    CPUEAXH_HOOK_MEM_WRITE_PROT,
    CPUEAXH_MEMORY_MODE_HOST,
    CPUEAXH_MEMORY_MODE_GUEST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RSP,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RIP,
    CpueaxhError,
    Engine,
)
from cpueaxh._loader import default_library_path


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

    def make_engine(self) -> Engine:
        return Engine(dll_path=str(self.dll_path))

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


if __name__ == "__main__":
    unittest.main()
