import traceback
import struct
import lz4.block
from .NxoHelper import NxoHelper, NxoSegment

class Nso0View(NxoHelper):
    name = 'NSO0'
    long_name = 'NSO0 Switch Executable'

    def __init__(self, parent_view):
        def r(offset, size):
            return parent_view.read(offset, size)
        def r32(offset):
            return struct.unpack('<I', r(offset, 4))[0]
        flags = r32(0xC)
        segs = {}
        for i, perm in enumerate(['rx', 'ro', 'rw']):
            foff = r32(0x10 + 0x10*i)
            voff = r32(0x14 + 0x10*i)
            size = r32(0x18 + 0x10*i)
            data = b''
            if flags & (1 << i):
                compressed_size = r32(0x60 + 4*i)
                data = r(foff, compressed_size)
                data = lz4.block.decompress(data, uncompressed_size=size)
            else:
                data = r(foff, size)
            segs[perm] = NxoSegment(voff, size, data)
        segs['rw'].size += r32(0x3c) # size of bss
        NxoHelper.__init__(self, parent_view, segs['rx'], segs['ro'], segs['rw'])

    @staticmethod
    def is_valid_for_data(data):
        return data.read(0, 4) == b'NSO0'

    def init(self):
        return True
