import binascii

from capstone import *
from capstone.x86 import *

highlighted_mnenomics = {"call", "jmp"}


def print_instruction(ins):
    if ins.mnemonic in highlighted_mnenomics:
        color = "\033[31m"
        color_end = "\033[0m"
    else:
        color = ""
        color_end = ""

    print(
        ("0x{:x}\t{:s}\t" + color + "{:s}" + color_end + " \t{:s}").format(
            ins.address,
            binascii.hexlify(
                ins.bytes).decode('utf-8').ljust(8),
            ins.mnemonic,
            ins.op_str).ljust(50))


def setup_capstone(doc):
    """ Set processor type and enable details of disassembled instructions"""
    if doc.processor == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif doc.processor == 'x86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif doc.processor == 'arm':
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        raise Exception("Mismatch in disassembly processor types")
    md.detail = True
    return md


def print_disassemble_proc(doc, md, adr):
    try:
        while doc.is_instruction(adr):
            # 15 bytes is the max intel-instruction length (ARM is less (?))
            ins = next(md.disasm(doc.bytes_at(adr, 15), adr, count=1))
            adr += ins.size
            print_instruction(ins)
    except StopIteration:
        return
