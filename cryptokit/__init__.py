from __future__ import unicode_literals
from future.builtins import range

from hashlib import sha256
from struct import pack, unpack
from collections import namedtuple
from binascii import unhexlify, hexlify


def sha256d(data):
    hsh = sha256(sha256(data).digest()).digest()
    return hsh


def _swap4(s):
    if len(s) % 4:
        raise ValueError()
    return ''.join(s[x:x+4][::-1] for x in range(0, len(s), 4))


def target_unpack(raw):
    """ Unpacks target given as 0x0404cb (as it's stored in block headers) and
    converts it to an integer. Expects a byte string. """
    assert len(raw) is 4
    mantissa = int(hexlify(raw[1:]), 16)
    exp = unpack(b"B", raw[0:1])[0]
    return mantissa * (2 ** (8 * (exp - 3)))


def bits_to_difficulty(bits):
    """ Takes bits as a hex string and returns the difficulty as a floating
    point number. """
    return 0xFFFF * (2 ** 208) / float(target_unpack(unhexlify(bits)))


def bits_to_shares(bits):
    """ Returns the estimated shares of difficulty 1 to calculate a block at
    a given difficulty. """
    return int(round(bits_to_difficulty(bits) * (0xFFFF + 1)))


def target_from_diff(
        difficulty,
        diff=0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF):
    return int(diff / difficulty)


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

    def varlen_decode(self, dat):
        """ Unpacks the variable count bytes present in several bitcoin
        objects. First byte signals overall length of and then byte lengths are
        reads accordingly. """
        if dat[0] == 0xff:
            return unpack(b'<Q', dat[1:9])[0], dat[9:]
        if dat[0] == 0xfe:
            return unpack(b'<L', dat[1:5])[0], dat[5:]
        if dat[0] == 0xfd:
            return unpack(b'<H', dat[1:3])[0], dat[3:]
        return dat[0], dat[1:]

    def varlen_encode(self, dat):
        """ This is the inverse of the above function, accepting a count and
        encoding that count """
        if dat < 0xfd:
            return pack(b'<B', dat)
        if dat <= 0xffff:
            return b'\xfd' + pack(b'<H', dat)
        if dat <= 0xffffffff:
            return b'\xfe' + pack(b'<L', dat)
        return b'\xff' + pack(b'<Q', dat)


def uint256_from_str(s):
    r = 0L
    t = unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def reverse_hash(h):
    # This only revert byte order, nothing more
    if len(h) != 64:
        raise Exception('hash must have 64 hexa chars')
    return ''.join([h[56 - i:64 - i] for i in range(0, 64, 8)])
