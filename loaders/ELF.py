import API
from .ELFHelper import ELF

# TODO: parse section headers if they are present and use them
# to push more code to the doc (from .dynsym)


def accept_file(f):
    """ Return true if the loader can parse this file"""
    f.seek(0)
    return f.read(4) == ELF.magic


def load_file(f, doc):
    """ Gets the content of file f and assemble it in address_space"""
    f.seek(0)
    buf = f.read()

    hdr = ELF(buf)
    doc.processor_type = hdr.processor_type()

    doc.push_proc(hdr.entrypoint())

    segments = hdr.segmentheaders()
    for seg in segments:
        #print("Copying from segment", seg, "to vaddr")
        virtual_off = seg.p_vaddr
        file_off = seg.p_offset
        # copy from file to virtual address space with the righ offsets
        for i in range(0, seg.p_filesz):
            doc.write_byte(virtual_off + i, buf[file_off + i])

    return doc
