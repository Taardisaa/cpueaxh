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
            0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, 42
        ]
    )

    with Engine() as engine:
        engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
        engine.mem_map(code_address, 0x1000, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
        engine.mem_write(code_address, code)
        engine.reg_write_u64(CPUEAXH_X86_REG_RIP, code_address)
        engine.emu_start(code_address, count=1)
        print(f"RAX = {engine.reg_read_u64(CPUEAXH_X86_REG_RAX)}")


if __name__ == "__main__":
    main()
