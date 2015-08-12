import binascii
from queue import PriorityQueue

from capstone import *
from capstone.x86 import *

import disassembler
import API


class Analyzer():

    def __init__(self, loader, f):
        """ Analyze a file f using a user-specified loader. It will start from the
        procedures given by the loader, then try a recursive descent from there, using
        a priority queue for handling branches."""

        self.queue = PriorityQueue()
        self.doc = API.Document()
        loader.load_file(f, self.doc)

        self.capstone_handle = disassembler.setup_capstone(self.doc)

        print(
            "Successfully loaded",
            f.name,
            "using loader",
            loader_name(loader))
        print("Analyzing...")
        self.analyze()
        print("Analysis complete")

        print("Found", len(self.doc.procedures), "procedures:")

        print("Skipping printing of procedures")
        # for proc in sorted(self.doc.procedures):
        #    print("Disassembly of", hex(proc))
        #    disassembler.print_disassemble_proc(self.doc, self.capstone_handle, proc)

    def queue_address(self, priority, address):
        # Don't queue already decoded addresses
        if self.doc.is_data(address):
            self.queue.put((priority, address))

    def dequeue_address(self):
        return self.queue.get()[1]

    def analyze(self):
        for proc in self.doc.proc_to_analyze:
            print("Adding proc at address", hex(proc), "(found by loader)")
            self.doc.set_procedure(proc)
            self.queue_address(10, proc)
        self.doc.proc_to_analyze = None

        self.heuristic_procedures()

        self.recursive_descent()
        print("Used " +
              str(len(self.doc.address_space.pages)) +
              " document pages for analysis")

    def heuristic_procedures(self):
        # TODO: mark procedures found by searching for "push esb, mov ebp esp"
        # x86: search for 55 89 E5
        pass

    def recursive_descent(self):
        """ Basic recursive descent using priority queues for branches"""
        while not self.queue.empty():
            adr = self.dequeue_address()

            # Don't disasm something if it has already been done (by something
            # with higher priority)
            if self.doc.is_instruction(
                    adr) or self.doc.is_instruction_body(adr):
                continue

            try:
                ins = next(
                    self.capstone_handle.disasm(
                        self.doc.bytes_at(
                            adr, 15), adr, count=1))
            except StopIteration:
                continue

            # print_instruction(ins)
            self.doc.set_instruction(adr, ins.size)
            if ins.id in conditionnal_branch_instructions or ins.id in branch_instructions:
                if ins.id in conditionnal_branch_instructions:
                    # Add next instruction too
                    # print("Adding", ins.mnemonic, "'s next to low priority")
                    self.queue.put((10, adr + ins.size))

                if ins.operands[0].type == X86_OP_IMM:
                    # print("Adding", ins.mnemonic, "'s operand to high priority")
                    self.queue.put((1, ins.operands[0].imm))
            else:
                # print("Adding", ins.mnemonic, "'s next to low priority")
                if ins.id not in stop_instruction:
                    self.queue.put((1, adr + ins.size))

            # mark procedure
            if ins.id in call_instructions and ins.operands[
                    0].type == X86_OP_IMM:
                self.doc.set_procedure(ins.operands[0].imm)


def loader_name(l):
    return l.__name__.split(".")[-1]

# TODO: add same groups for ARM/X86_64/...
branch_instructions = {
    X86_INS_LJMP,
    X86_INS_JMP
}

stop_instruction = {
    X86_INS_RET,
    X86_INS_JMP,
    X86_INS_LJMP,
}

conditionnal_branch_instructions = {
    X86_INS_JAE,
    X86_INS_JA,
    X86_INS_JBE,
    X86_INS_JB,
    X86_INS_JCXZ,
    X86_INS_JECXZ,
    X86_INS_JE,
    X86_INS_JGE,
    X86_INS_JG,
    X86_INS_JLE,
    X86_INS_JL,
    X86_INS_JMP,
    X86_INS_JNE,
    X86_INS_JNO,
    X86_INS_JNP,
    X86_INS_JNS,
    X86_INS_JO,
    X86_INS_JP,
    X86_INS_JRCXZ,
    X86_INS_JS,
    X86_INS_CALL,
    X86_INS_LCALL,
}

call_instructions = {
    X86_INS_CALL,
    X86_INS_LCALL,
}
