from __future__ import unicode_literals
from future.builtins import range

from hashlib import sha256
from StringIO import StringIO

import struct
import binascii


def sha256d(data):
    return hsh


def _swap4(s):
    if len(s) % 4:
        raise ValueError()
    return ''.join(s[x:x+4][::-1] for x in range(0, len(s), 4))


def parse_bc_int(f):
    v = ord(f.read(1))
    if v == 253:
        v = struct.unpack("<H", f.read(2))[0]
    elif v == 254:
        v = struct.unpack("<L", f.read(4))[0]
    elif v == 255:
        v = struct.unpack("<Q", f.read(8))[0]
    return v


def parse_bc_string(f):
    size = parse_bc_int(f)
    return f.read(size)


def stream_bc_int(f, v):
    if v < 253:
        f.write(struct.pack("<B", v))
    elif v <= 65535:
        f.write(b'\xfd' + struct.pack("<H", v))
    elif v <= 0xffffffff:
        f.write(b'\xfe' + struct.pack("<L", v))
    else:
        f.write(b'\xff' + struct.pack("<Q", v))


def stream_bc_string(f, v):
    stream_bc_int(f, len(v))
    f.write(v)


class Hash(int):
    """ Helper object for dealing with hash encoding. Most functions from
    bitcoind deal with little-endian values while most consumer use
    big-endian. """
    @classmethod
    def from_le(cls, data):
        return cls(binascii.hexlify(data[::-1]), 16)

    @classmethod
    def from_be(cls, data):
        return cls(binascii.hexlify(data), 16)

    @property
    def le(self):
        return binascii.unhexlify("%16x" % (self,))[::-1]

    @property
    def be(self):
        return binascii.unhexlify("%16x" % (self,))

    @classmethod
    def from_sha256d(cls, data):
        return cls.from_be(sha256(sha256(data).digest()).digest())


class BitcoinEncoding(object):
    @classmethod
    def from_hex(cls, hex_data):
        return cls.from_stream(StringIO(binascii.unhexlify(hex_data)))

    @classmethod
    def from_bytes(cls, data):
        return cls.from_stream(StringIO(data))

    def to_hex(cls):
        return cls.to_stream().read()

    def to_bytes(cls):
        f = StringIO()
        cls.to_stream(f)
        f.seek(0)
        return f.read()
