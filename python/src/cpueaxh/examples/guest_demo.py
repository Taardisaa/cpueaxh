from cpueaxh import (
    CPUEAXH_MEMORY_MODE_GUEST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RIP,
    Engine,
)


def main() -> None:
    code_address = 0x1000
    code = bytes(
        [
            0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    )

    with Engine() as engine:
        engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
        engine.map_memory(code_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
        engine.write_memory(code_address, code)
        engine.write_register_u64(CPUEAXH_X86_REG_RIP, code_address)
        engine.start(code_address, count=1)
        print(f"Loaded DLL: {engine.dll_path}")
        print(f"RAX = {engine.read_register_u64(CPUEAXH_X86_REG_RAX)}")


if __name__ == "__main__":
    main()
