from __future__ import unicode_literals
from future.builtins import bytes, range

import struct

from hashlib import sha256
from collections import namedtuple
from binascii import hexlify

from . import BitcoinEncoding, Hash, parse_bc_string, parse_bc_int
from .base58 import address_bytes
from .bitcoin.script import create_push_script


class Input(namedtuple(
        'Input', ['prevout_hash', 'prevout_idx', 'script_sig', 'seqno'])):
    """ An individual input to a transaction. """

    @classmethod
    def from_stream(cls, f):
        return cls(
            prevout_hash=Hash.from_le(f.read(32)),
            prevout_idx=struct.unpack("<L"),
            script_sig=parse_bc_string(f),
            seqno=struct.unpack("<L")
        )

    def to_stream(self, f):
        f.write(self.prevout_hash.le)
        f.write(struct.pack("<L", self.prevout_idx))
        f.write(struct.pack("<L", self.prevout_idx))

    @classmethod
    def coinbase(cls, height=None, addtl_push=None, extra_script_sig=b''):
        if not addtl_push:
            addtl_push = []
        # Meet BIP 34 by adding the height of the block
        # encode variable length integer
        data = create_push_script([height] + addtl_push)
        return cls(
            prevout_hash=Transaction._nullprev,
            prevout_idx=4294967295,
            script_sig=data + extra_script_sig,
            seqno=0)


class Output(namedtuple('Output', ['amount', 'script_pub_key'])):
    """ script_pub_key is a byte string. Amount is an integer. """
    @classmethod
    def to_address(cls, amount, address):
        """ Creates an output with a script_pub_key that sends the funds to a
        specific address. Address should be given as a base58 string. """
        raw_addr = address_bytes(address)
        return cls(amount, b'\x76\xa9\x14' + raw_addr + b'\x88\xac')


class Transaction(BitcoinEncoding):
    """ An object wrapper for a bitcoin transaction. More information on the
    raw format at https://en.bitcoin.it/wiki/Transactions. """
    _nullprev = b'\0' * 32

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.locktime = 0
        self.version = 1

    def from_stream(cls, f):
        self = cls()
        self.version, = struct.unpack("<L", f)
        input_count = parse_bc_int(f)
        for i in range(input_count):
            self.inputs.append(Input.parse(f))
        output_count = parse_bc_int(f)
        for i in range(output_count):
            self.outputs.append(Output.parse(f))
        lock_time, = struct.unpack("<L", f)
        return self

    def to_stream(self, f):
        """ Reverse of disassemble, pack up the object into a byte string raw
        transaction. """
        f.write(struct.pack('<L', self.version))
        f.write(self.varlen_encode(len(self.inputs)))
        for prevout_hash, prevout_idx, script_sig, seqno in self.inputs:
            data += prevout_hash
            data += pack(b'<L', prevout_idx)
            data += self.varlen_encode(len(script_sig))
            data += script_sig
            split_point = len(data)
            data += pack(b'<L', seqno)

        data += self.varlen_encode(len(self.outputs))
        for amount, script_pub_key in self.outputs:
            data += pack(b'<Q', amount)
            data += self.varlen_encode(len(script_pub_key))
            data += script_pub_key

        data += pack(b'<L', self.locktime)

        self._raw = data
        # reset hash to be recacluated on next grab
        self._hash = None
        if split:
            return data[:split_point], data[split_point:]
        return data

    @property
    def raw(self):
        if self._raw is None:
            self.assemble()
        return self._raw

    @property
    def hash(self):
        """ Compute the hash of the transaction when needed """
        if self._hash is None:
            self._hash = sha256(sha256(self._raw).digest()).digest()[::-1]
        return self._hash
    lehash = hash

    @property
    def behash(self):
        return self.hash[::-1]

    @property
    def lehexhash(self):
        return hexlify(self.hash)

    @property
    def behexhash(self):
        return hexlify(self.hash[::-1])

    def __hash__(self):
        return unpack(b'i', self.hash)[0]

    def to_dict(self):
        return {'inputs': [{'prevout_hash': hexlify(inp[0]),
                            'prevout_idx': inp[1],
                            'script_sig': hexlify(inp[2]),
                            'seqno': inp[3]} for inp in self.inputs],
                'outputs': [{'amount': out[0],
                             'script_pub_key': hexlify(out[1])}
                            for out in self.outputs],
                'data': hexlify(self._raw),
                'locktime': self.locktime,
                'version': self.version,
                'hash': self.lehexhash}
