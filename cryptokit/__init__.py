from __future__ import unicode_literals
from future.builtins import range

from hashlib import sha256

import struct
import binascii


def sha256d(data):
    hsh = sha256(sha256(data).digest()).digest()
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


class BitcoinEncoding(object):

    def varlen_decode(self, dat):
        """ Unpacks the variable count bytes present in several bitcoin
        objects. First byte signals overall length of and then byte lengths are
        reads accordingly. """
        if dat[0] == 0xff:
            return struct.unpack(b'<Q', dat[1:9])[0], dat[9:]
        if dat[0] == 0xfe:
            return struct.unpack(b'<L', dat[1:5])[0], dat[5:]
        if dat[0] == 0xfd:
            return struct.unpack(b'<H', dat[1:3])[0], dat[3:]
        return dat[0], dat[1:]

    def varlen_encode(self, dat):
        """ This is the inverse of the above function, accepting a count and
        encoding that count """
        if dat < 0xfd:
            return struct.pack(b'<B', dat)
        if dat <= 0xffff:
            return b'\xfd' + struct.pack(b'<H', dat)
        if dat <= 0xffffffff:
            return b'\xfe' + struct.pack(b'<L', dat)
        return b'\xff' + struct.pack(b'<Q', dat)


def uint256_from_str(s):
    r = 0L
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def reverse_hash(h):
    # This only revert byte order, nothing more
    if len(h) != 64:
        raise Exception('hash must have 64 hexa chars')
    return ''.join([h[56 - i:64 - i] for i in range(0, 64, 8)])
