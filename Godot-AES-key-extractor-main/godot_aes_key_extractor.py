import pefile

FILE_NAME = ".exe"
AES_KEY_SIZE = 32

def is_valid_lea_instruction(inst):
    """Check if the given instruction is a valid LEA instruction."""
    return (inst.reg_name(inst.operands[0].value.reg) in ("r12", "r13", "r14", "r15") and
            inst.reg_name(inst.operands[1].value.mem.base) == "rip")

def is_address_within_section_bounds(address, section):
    """Check if the given address is within the bounds of the given section."""
    return (address >= section.VirtualAddress and
            address < section.VirtualAddress + section.Misc_VirtualSize)

def main():
    try:
        pe = pefile.PE(FILE_NAME)
    except Exception as e:
        print(f"Error parsing binary: {e}")
        return

    # 查找 .text 和 .data 节
    text_section = None
    data_section = None
    for section in pe.sections:
        if b'.text' in section.Name:
            text_section = section
        elif b'.data' in section.Name:
            data_section = section

    if text_section is None or data_section is None:
        print("Unable to find .text or .data sections.")
        return

    # 输出 .text 和 .data 节的信息
    print(f"Text Section: {hex(text_section.VirtualAddress)}-{hex(text_section.VirtualAddress + text_section.Misc_VirtualSize)}")
    print(f"Data Section: {hex(data_section.VirtualAddress)}-{hex(data_section.VirtualAddress + data_section.Misc_VirtualSize)}")

    # 使用 Capstone 解析 .text 节中的 LEA 指令
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = md.skipdata = True

    for inst in md.disasm(bytes(text_section.get_data()), text_section.VirtualAddress):
        if inst.mnemonic == "lea" and is_valid_lea_instruction(inst):
            ref_address = inst.address + inst.size + inst.operands[1].value.mem.disp
            if is_address_within_section_bounds(ref_address, data_section):
                ref_bytes = pe.get_data(ref_address, AES_KEY_SIZE)
                if b"\x00" not in ref_bytes:
                    print(f"Potential AES key found at address 0x{ref_address:x}: {''.join(f'{byte:02x}' for byte in ref_bytes)}")

if __name__ == '__main__':
    main()
