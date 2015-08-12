"""
    A document that represent the virtual address space of an exectutable loaded in memory.
    It contains metadata regarding for each byte.

    This module is used by a file loader to set-up the binary, and to support analysis and
    disassembly.
"""
from SparseBytes import SparseBytes

import ctypes
uint8_t = ctypes.c_uint8


# A memory efficient struct to represent the usefulness of the byte
class Meta(ctypes.LittleEndianStructure):
    _fields_ = [
        ("type", uint8_t, 2),
        ("procedure", uint8_t, 1),
    ]


def make_meta(n, dummy):
    nMetaArray = Meta * n
    return nMetaArray()


# 2 bits field for byte content type
# can be augmented to mark procedure start, etc
_META_VALUES = {
    "data": 0,
    "undefined": 1,          # byte that doesn't exist in the binary
    "instruction": 2,        # first byte of instruction
    "instruction_body": 3,   # non-first byte of instruction
}

processors = ['x86', 'x86_64', 'arm']


class Document():

    """ A Document represents the virtual address space of the binary,
    with associated meta data like type (instruction start or body) """

    def __init__(self):
        self.address_space = SparseBytes()
        self.meta = SparseBytes(undefined_value=_META_VALUES["undefined"],
                                array_constructor=make_meta)
        self.processor = processors[0]  # A default processor value
        self.procedures = []
        self.proc_to_analyze = []

    # used by the loader to push address of procedure to analyze later
    def push_proc(self, address):
        self.proc_to_analyze.append(address)

    def set_processor(self, processor):
        self.processor = processor

    def set_instruction(self, adr, size):
        self.meta[adr].type = _META_VALUES["instruction"]
        for i in range(adr + 1, adr + size):
            self.set_instruction_body(i)

    # Used by the analyzer to mark a procedure start - loader please keep out
    def set_procedure(self, adr):
        print("Found proc at", hex(adr))
        self.procedures.append(adr)
        self.meta[adr].procedure = True

    def is_instruction(self, adr):
        return self.meta[adr].type == _META_VALUES["instruction"]

    def set_instruction_body(self, adr):
        self.meta[adr].type = _META_VALUES["instruction_body"]

    def is_instruction_body(self, adr):
        return self.meta[adr].type == _META_VALUES["instruction_body"]

    def set_data(self, adr):
        self.meta[adr].type = _META_VALUES["data"]

    def is_data(self, adr):
        return self.meta[adr].type == _META_VALUES["data"]

    def is_undefined(self, adr):
        try:
            return self.meta[adr].type == _META_VALUES["undefined"]
        except KeyError:
            return True

    def write_byte(self, adr, byte):
        """Used by loaders to write a byte from binary to virtual
        address_space, defaulting to data"""
        self.address_space[adr] = byte
        # when a byte is written, it's data until proven otherwise
        self.meta[adr] = Meta(0)  # will create the page if empty
        self.meta[adr].type = _META_VALUES["data"]

    def bytes_at(self, adr, length):
        """Returns a bytearray of bytes at adr, of length length,
        or less if the bytes weren't set"""
        for i in range(length):
            if self.is_undefined(adr + i):
                length = i
                break
        return self.address_space.bytes_at(adr, length)

    def serialize(self, outpath):
        """ TODO: Save/pickle the document for future reopening"""
        pass
