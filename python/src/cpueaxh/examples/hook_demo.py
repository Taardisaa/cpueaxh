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


def main() -> None:
    code_address = 0x2000
    code = bytes(
        [
            0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # mov rax, 42
            0x48, 0x83, 0xC0, 0x01,                                      # add rax, 1
        ]
    )

    with Engine() as engine:
        engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
        engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)
        engine.write_register_u64(CPUEAXH_X86_REG_RIP, code_address)

        def on_pre(address: int) -> None:
            print(f"pre-hook @ 0x{address:016X}")

        hook = engine.add_code_hook(CPUEAXH_HOOK_CODE_PRE, on_pre, code_address, code_address + len(code) - 1)
        try:
            engine.start(code_address, count=2)
        finally:
            engine.delete_hook(hook)

        print(f"RAX = {engine.read_register_u64(CPUEAXH_X86_REG_RAX)}")


if __name__ == "__main__":
    main()
