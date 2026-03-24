from cpueaxh import (
    CPUEAXH_ESCAPE_INSN_CPUID,
    CPUEAXH_ESCAPE_INSN_XGETBV,
    CPUEAXH_X86_REG_RAX,
    CPUEAXH_X86_REG_RBX,
    CPUEAXH_X86_REG_RCX,
    CPUEAXH_X86_REG_RDX,
    HostBridgeSession,
    NativeBridgeLibrary,
)


def main() -> None:
    cpuid_code = bytes(
        [
            0xB8, 0x00, 0x00, 0x00, 0x00,  # mov eax, 0
            0x31, 0xC9,                    # xor ecx, ecx
            0x0F, 0xA2,                    # cpuid
        ]
    )
    xgetbv_code = bytes(
        [
            0x31, 0xC9,                    # xor ecx, ecx
            0x0F, 0x01, 0xD0,              # xgetbv
        ]
    )
    bridges = NativeBridgeLibrary()
    cpuid_bridge = bridges.symbol("cpueaxh_example_execute_cpuid")
    xgetbv_bridge = bridges.symbol("cpueaxh_example_execute_xgetbv")

    with HostBridgeSession() as session:
        _, cpuid_address = session.load_code(cpuid_code)
        cpuid_escape = session.add_host_call_escape(
            CPUEAXH_ESCAPE_INSN_CPUID,
            cpuid_bridge,
            cpuid_address,
            cpuid_address + len(cpuid_code) - 1,
        )
        try:
            session.start(cpuid_address, count=3)
        finally:
            session.engine.delete_escape(cpuid_escape)

        print(f"CPUID RAX = 0x{session.engine.read_register_u64(CPUEAXH_X86_REG_RAX):08X}")
        print(f"CPUID RBX = 0x{session.engine.read_register_u64(CPUEAXH_X86_REG_RBX):08X}")
        print(f"CPUID RCX = 0x{session.engine.read_register_u64(CPUEAXH_X86_REG_RCX):08X}")
        print(f"CPUID RDX = 0x{session.engine.read_register_u64(CPUEAXH_X86_REG_RDX):08X}")

    with HostBridgeSession() as session:
        _, xgetbv_address = session.load_code(xgetbv_code)
        xgetbv_escape = session.add_host_call_escape(
            CPUEAXH_ESCAPE_INSN_XGETBV,
            xgetbv_bridge,
            xgetbv_address,
            xgetbv_address + len(xgetbv_code) - 1,
        )
        try:
            session.start(xgetbv_address, count=2)
        finally:
            session.engine.delete_escape(xgetbv_escape)

        eax = session.engine.read_register_u64(CPUEAXH_X86_REG_RAX) & 0xFFFFFFFF
        edx = session.engine.read_register_u64(CPUEAXH_X86_REG_RDX) & 0xFFFFFFFF
        print(f"XGETBV EAX = 0x{eax:08X}")
        print(f"XGETBV EDX = 0x{edx:08X}")


if __name__ == "__main__":
    main()
