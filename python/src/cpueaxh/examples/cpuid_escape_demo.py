from cpueaxh import (
    CPUEAXH_ESCAPE_INSN_CPUID,
    CPUEAXH_MEMORY_MODE_GUEST,
    CPUEAXH_PROT_EXEC,
    CPUEAXH_PROT_READ,
    CPUEAXH_PROT_WRITE,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RBX,
    CPUEAXH_X86_REG_RCX,
    CPUEAXH_X86_REG_RDX,
    Engine,
)


def main() -> None:
    code_address = 0x5000
    code = bytes(
        [
            0xB8, 0x01, 0x00, 0x00, 0x00,  # mov eax, 1
            0x31, 0xC9,                    # xor ecx, ecx
            0x0F, 0xA2,                    # cpuid
        ]
    )

    with Engine() as engine:
        engine.set_memory_mode(CPUEAXH_MEMORY_MODE_GUEST)
        engine.load_code(code_address, code, CPUEAXH_PROT_READ | CPUEAXH_PROT_WRITE | CPUEAXH_PROT_EXEC)

        def on_cpuid(context) -> None:
            leaf = int(context.regs[CPUEAXH_X86_REG_RAX] & 0xFFFFFFFF)
            subleaf = int(context.regs[CPUEAXH_X86_REG_RCX] & 0xFFFFFFFF)
            print(f"escape cpuid leaf=0x{leaf:08X} subleaf=0x{subleaf:08X}")
            context.regs[CPUEAXH_X86_REG_RAX] = 0x12345678
            context.regs[CPUEAXH_X86_REG_RBX] = 0x87654321
            context.regs[CPUEAXH_X86_REG_RCX] = 0xAABBCCDD
            context.regs[CPUEAXH_X86_REG_RDX] = 0x0BADF00D

        escape = engine.add_escape(CPUEAXH_ESCAPE_INSN_CPUID, on_cpuid, code_address, code_address + len(code) - 1)
        try:
            engine.start(code_address, count=3)
        finally:
            engine.delete_escape(escape)

        print(f"RAX = 0x{engine.read_register_u64(CPUEAXH_X86_REG_RAX):08X}")
        print(f"RBX = 0x{engine.read_register_u64(CPUEAXH_X86_REG_RBX):08X}")
        print(f"RCX = 0x{engine.read_register_u64(CPUEAXH_X86_REG_RCX):08X}")
        print(f"RDX = 0x{engine.read_register_u64(CPUEAXH_X86_REG_RDX):08X}")


if __name__ == "__main__":
    main()
