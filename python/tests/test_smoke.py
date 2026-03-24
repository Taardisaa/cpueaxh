import sys
import unittest
from pathlib import Path

from cpueaxh import (
    CPUEAXH_HOOK_CODE_PRE,
    CPUEAXH_MEMORY_MODE_GUEST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RIP,
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


if __name__ == "__main__":
    unittest.main()
