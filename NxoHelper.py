from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.log import log_error, log_info
from binaryninja.databuffer import DataBuffer
from binaryninja import _binaryninjacore as core

try: xrange
except NameError: xrange = range

class NxoSegment:
    def __init__(self, addr, size, data):
        log_info('addr' + repr(addr))
        log_info('size' + repr(size))
        log_info('data' + repr(len(data)))
        if (size & 0xfff) != 0:
            size += 0xfff
            size &= ~0xfff
        if len(data) < size:
            data += b'\x00' * (size - len(data))
        self.addr = addr
        self.size = size
        self.data = data

    def contains(self, addr):
        return addr in xrange(self.addr, self.addr + self.size)

    def contains_range(self, addr, length):
        return self.contains(addr) and self.contains(addr + length)

class NxoHelper(BinaryView):
    def __init__(self, parent_view, rx, ro, rw):
        def align4k(data):
            size = len(data)
            size = (size + 0xfff) &~ 0xfff
            return data + (b'\x00'*(size - len(data)))
        view_data = align4k(rx.data) + align4k(ro.data) + align4k(rw.data)
        #
        # Because the binary is compressed, we cannot use a file-parent-backed
        # BinaryView. And a Python-implemented BinaryView turned out extremely
        # slow. So, for performance reasons, we need a DataBuffer-backed
        # BinaryView. This seems not supported by the documented Binary Ninja
        # API, so we need to call into core.
        #
        # We cannot support relocations at the moment, because a BinaryDataView
        # is always based at 0, and I don't know how to get around that.
        #
        view_buffer = DataBuffer(view_data)
        view = core.BNCreateBinaryDataViewFromBuffer(parent_view.file.handle, view_buffer.handle)
        BinaryView.__init__(self, file_metadata=parent_view.file, handle=view)
        self.platform = Architecture['aarch64'].standalone_platform
        # Store a reference to prevent UAF crash (?)
        self.ref = view_buffer
        self.segs = {
            'rx': rx,
            'ro': ro,
            'rw': rw,
        }
        for p in self.segs.keys():
            sf = 0
            ss = 0
            if 'r' in p:
                sf |= SegmentFlag.SegmentReadable
                ss = SectionSemantics.ReadOnlyDataSectionSemantics
            if 'w' in p:
                sf |= SegmentFlag.SegmentWritable
                ss = SectionSemantics.ReadWriteDataSectionSemantics
            if 'x' in p:
                sf |= SegmentFlag.SegmentExecutable
                ss = SectionSemantics.ReadOnlyCodeSectionSemantics
            s = self.segs[p]
            self.add_auto_section(p, s.addr, s.size, ss)
        self.reanalyze()
