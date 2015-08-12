#!/usr/bin/env python3

import binascii
from struct import unpack
from collections import namedtuple

ProgramHeader = namedtuple("ProgramHeader", "p_offset, p_vaddr, p_filesz")

# def print_program_header(ph):
#    print("offset:", hex(ph.p_offset), "\tvaddr:", hex(
#        ph.p_vaddr), "\tfilesz:", hex(ph.p_filesz))


def check(condition, message):
    if not condition:
        raise Exception(message)


class ELF:
    magic = b"\x7fELF"

    def __init__(self, buf):
        """ Init an ELF header from a binary buffer"""
        self.buf = buf
        if unpack('xxxxc', buf[:0x5]) == (b'\x01',):
            self.is32bits = True
        else:
            self.is32bits = False

    def entrypoint(self):
        """ Returns the virtual address of the entry point"""
        if self.is32bits:
            ep, = unpack('I', self.buf[24:28])
        else:
            ep, = unpack('Q', self.buf[24:32])
        return ep

    def processor_type(self):
        """ Return the processor type of the ELF, (name matching API.processors)"""
        processors = {
            0x03: "x86",
            0x28: "arm",
            0x3E: "x86_64",
        }
        pt, = unpack('H', self.buf[0x12:0x14])
        return processors[pt]

    def segmentheaders(self):
        """ Returns a list of the segments (program)  headers"""
        # Get the program header size, offset in binary, and number
        if self.is32bits:
            phoff, = unpack('I', self.buf[0x1c: 0x1c + 4])
            phentsize, = unpack('H', self.buf[0x2a:0x2a + 2])
            phnum, = unpack('H', self.buf[0x2c: 0x2c + 2])
        else:
            phoff, = unpack('Q', self.buf[0x20: 0x20 + 8])
            phentsize, = unpack('H', self.buf[0x36:0x36 + 2])
            phnum, = unpack('H', self.buf[0x38: 0x38 + 2])

        #print("phoff=%x \t phnum=%x \t phentsize=%x \t 32bits=%r", phoff, phnum, phentsize, self.is32bits)

        # Reference: http://www.sco.com/developers/gabi/latest/ch5.pheader.html
        pheaders = []
        for adr in range(phoff, phoff + phentsize * phnum, phentsize):
            if self.is32bits:
                p_offset, p_vaddr, p_filesz = unpack(
                    'xxxx II xxxx I xxxx xxxx xxxx', self.buf[
                        adr: adr + phentsize])
            else:
                p_offset, p_vaddr, p_filesz = unpack(
                    'xxxx xxxx Q Q xxxxxxxx Q xxxxxxxx xxxxxxxx ', self.buf[
                        adr: adr + phentsize])
            pheaders.append(ProgramHeader(p_offset, p_vaddr, p_filesz))

        return pheaders


def test():
    with open('test_files/dummy_C_64', 'rb') as f:
        code64 = f.read()
    e64 = ELF(code64)

    check(e64.is32bits == False, "bitness recognition failed")
    check(e64.entrypoint() == 0x400440, "entrypoint recognition failed")

    e64_seg = e64.segmentheaders()

    check(len(e64_seg) == 9, "wrong segment count in 64 bits binary")
    check(e64_seg[0].p_offset == 0x40, "wrong p_offset in 64 bits binary")

    with open('test_files/tiny_crackme', 'rb') as f:
        tiny = f.read()
    e_tiny = ELF(tiny)

    check(e_tiny.is32bits, "bitness recognition failed")
    check(e_tiny.entrypoint() == 0x200008, "entrypoint recognition failed")

    et_seg = e_tiny.segmentheaders()[0]
    check(
        et_seg.p_offset == 0 and et_seg.p_vaddr == 0x200000 and et_seg.p_filesz == 0x31b,
        "wrong tiny segment recognition")

    print("... ::: All test passed ::: ...")

if __name__ == '__main__':
    test()
