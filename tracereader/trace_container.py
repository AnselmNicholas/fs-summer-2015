import sys
import struct

import pb.piqi_pb2 as piqi_pb2

class TraceException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class TraceContainerReader:
    HEADER_SIZE = 48
    MAGIC = 7456879624156307493
    MAGIC_OFFSET = 0
    VERSION_OFFSET = 8
    BFD_ARCH_OFFSET = 16
    BFD_MACHINE_OFFSET = 24
    NUM_FRAMES_OFFSET = 32
    TOC_OFFSET_OFFSET = 40
    FIRST_FRAME_OFFSET = 48

    HIGHEST_VERSION = 1
    LOWEST_VERSION = 1

    def __init__(self, filename):
        try:
            self.f = open(filename, 'rb')
        except:
            raise TraceException('Unable to open trace for reading')

        header = self.f.read(self.HEADER_SIZE)

        magic = struct.unpack_from('<Q', header, self.MAGIC_OFFSET)[0]
        if magic != self.MAGIC:
            raise TraceException('Magic number not found in trace')

        version = struct.unpack_from('<Q', header, self.VERSION_OFFSET)[0]

        if version > self.HIGHEST_VERSION or \
           version < self.LOWEST_VERSION:
            raise TraceException('Unsupported trace version')

        arch = struct.unpack_from('<Q', header, self.BFD_ARCH_OFFSET)[0]
        mach = struct.unpack_from('<Q', header, self.BFD_MACHINE_OFFSET)[0]

        # number of frames
        self.num_frames = struct.unpack_from('<Q', header, self.NUM_FRAMES_OFFSET)[0]

        # offset where the toc is stored
        self.toc_offset = struct.unpack_from('<Q', header, self.TOC_OFFSET_OFFSET)[0]

        # seek to the toc
        self.f.seek(self.toc_offset, 0)

        # number of toc entries
        self.frames_per_toc_entry = struct.unpack('<Q', self.f.read(8))[0]

        self.toc = []

        # read toc entries
        for i in xrange(0, (self.num_frames - 1) / self.frames_per_toc_entry):
            offset = struct.unpack('<Q', self.f.read(8))[0]

            self.toc.append(offset)

        # check that we're at the end of the file
        us = self.f.tell()
        self.f.seek(0, 2)

        if us != self.f.tell():
            raise TraceException('The table of contents is malformed.')

        self.seek(0)

    def seek(self, index):
        if index >= self.num_frames:
            raise TraceException('seek() to non-existant frame')

        toc_number = index / self.frames_per_toc_entry

        if toc_number == 0:
            self.current_frame = 0
            self.f.seek(self.FIRST_FRAME_OFFSET, 0)
        else:
            self.current_frame = toc_number * self.frames_per_toc_entry
            self.f.seek(self.toc[toc_number-1], 0)

        while self.current_frame != index:
            frame_len = struct.unpack('<Q', self.f.read(8))[0]

            self.f.seek(frame_len, 1)
            self.current_frame = self.current_frame + 1

    def get_frame(self):
        if self.current_frame >= self.num_frames:
            raise TraceException('seek() to non-existant frame')

        frame_len = struct.unpack('<Q', self.f.read(8))[0]
        if frame_len == 0:
            raise TraceException('Read zero-length frame at offset ' + self.f.tell())

        frame_str = self.f.read(frame_len)

        frame = piqi_pb2.frame()
        frame.ParseFromString(frame_str)

        return frame
