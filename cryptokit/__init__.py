from __future__ import unicode_literals
from future.builtins import (bytes, range)
from struct import pack, unpack
from collections import namedtuple
from binascii import unhexlify, hexlify


def target_unpack(raw):
    """ Unpacks target given as 0x0404cb (as it's stored in block headers) and
    converts it to an integer. Expects a byte string. """
    assert len(raw) is 4
    mantissa = int(hexlify(raw[1:]), 16)
    exp = unpack(str("B"), raw[0:1])[0]
    return mantissa * (2 ** (8 * (exp - 3)))


def target_pack(hex_num):
    pass


def target_from_diff(
    difficulty,
    diff=0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
    return difficulty * diff


class Hash(namedtuple('Hash', ['hash'], verbose=False)):
    """ Helper object for dealing with hash encoding. Most functions from
    bitcoind deal with little-endian values while most consumer use
    big-endian. """
    @classmethod
    def from_le_bytes(cls, by):
        return cls(by)

    @classmethod
    def from_be_bytes(cls, by):
        return cls(by[::-1])

    @classmethod
    def from_be_hex(cls, by):
        return cls(unhexlify(by[::-1]))

    @classmethod
    def from_le_hex(cls, by):
        return cls(unhexlify(by))

    @property
    def le_hex(self):
        return hexlify(self[0]).decode('ascii')

    @property
    def be_hex(self):
        return hexlify(self[0][::-1]).decode('ascii')

    @property
    def le_bytes(self):
        return self[0]

    @property
    def be_bytes(self):
        return self[0][::-1]

    def sha(self, other):
        return Hash.from_be_bytes(sha256(sha256(
            self.be_bytes + other.be_bytes).digest()).digest())


class BitcoinEncoding(object):

    def varlen_decode(self, byte_string):
        """ Unpacks the variable count bytes present in several bitcoin
        objects. First byte signals overall length of and then byte lengths are
        reads accordingly. """
        if byte_string[0] == 0xff:
            return self.unpack('<Q', byte_string[1:9]), byte_string[9:]
        if byte_string[0] == 0xfe:
            return self.unpack('<L', byte_string[1:5]), byte_string[5:]
        if byte_string[0] == 0xfd:
            return self.funpack('<H', byte_string[1:3]), byte_string[3:]
        return byte_string[0], byte_string[1:]

    def varlen_encode(self, number):
        """ This is the inverse of the above function, accepting a count and
        encoding that count """
        if number < 0xfd:
            return pack(str('<B'), number)
        if number <= 0xffff:
            return b'\xfd' + pack(str('<H'), number)
        if number <= 0xffffffff:
            return b'\xfe' + pack(str('<L'), number)
        return b'\xff' + pack(str('<Q'), number)

    def funpack(self, *args, **kwargs):
        """ Helper for the common act of unpacking a single item """
        return unpack(str(args[0]), *args[1:], **kwargs)[0]
