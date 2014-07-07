import struct
import binascii
from struct import pack


def ser_vector(l):
    r = ""
    if len(l) < 253:
        r = chr(len(l))
    elif len(l) < 0x10000:
        r = chr(253) + pack("<H", len(l))
    elif len(l) < 0x100000000L:
        r = chr(254) + pack("<I", len(l))
    else:
        r = chr(255) + pack("<Q", len(l))
    for i in l:
        r += i.serialize()
    return r


def deser_string(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return f.read(nit)


def ser_string(s):
    if len(s) < 253:
        return chr(len(s)) + s
    elif len(s) < 0x10000:
        return chr(253) + struct.pack("<H", len(s)) + s
    elif len(s) < 0x100000000L:
        return chr(254) + struct.pack("<I", len(s)) + s
    return chr(255) + struct.pack("<Q", len(s)) + s


class CMasterNodeVote(object):
    def __init__(self):
        """int votes;
        CScript pubkey;
        int64 blockHeight"""

        self.blockHeight = 0
        self.scriptPubKey = ""
        self.votes = 0

    def deserialize(self, f):
        self.blockHeight = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)
        self.votes = struct.unpack("<i", f.read(4))[0]

    def serialize(self):
        r = ""
        r += struct.pack("<q", self.blockHeight)
        r += ser_string(self.scriptPubKey)
        r += struct.pack("<i", self.votes)
        print "mnv", self.scriptPubKey, ser_string(self.scriptPubKey)
        return r

    def __repr__(self):
        return "CMasterNodeVote(blockHeight=%d scriptPubKey=%s, votes=%d)" % (self.blockHeight, binascii.hexlify(self.scriptPubKey), self.votes)
