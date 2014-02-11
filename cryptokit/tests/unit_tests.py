from __future__ import unicode_literals
from future.builtins import bytes, range

import unittest

from cryptokit.base58 import get_bcaddress_version, b58encode, b58decode
from cryptokit import target_unpack, target_from_diff
from cryptokit.transaction import Input
from cryptokit.block import BlockTemplate
from cryptokit import Hash

from hashlib import sha256
from binascii import unhexlify, hexlify


class TestHashTuple(unittest.TestCase):
    def test_hash_hex(self):
        hsh = Hash.from_be_hex(
            "c8a78165527ab2022a57b095fef86c83e472b7d639cc246c3b40623c374fed4d")
        self.assertEquals(
            "d4def473c32604b3c642cc936d7b274e38c68fef590b75a2202ba72556187a8c",
            hsh.le_hex)
        self.assertEquals(
            "8c7a185625a72b20a2750b59ef8fc6384e277b6d93cc42c6b30426c373f4ded4",
            hsh.be_hex)


class TestBlockTemplate(unittest.TestCase):
    def test_validate_scrypt(self):
        """ confirm scrypt validation of difficulty works properly """
        header_hex = ("01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3"
                      "b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509b"
                      "d073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4")
        header_bytes = header_hex.decode('hex')
        target = target_unpack(unhexlify("1d018ea7"))

        self.assertTrue(BlockTemplate.validate_scrypt(header_bytes, target))


class TestInput(unittest.TestCase):
    def test_coinbase_numeric(self):
        inp = Input.coinbase(120000)
        assert int.from_bytes(inp.script_sig[1:], byteorder='little') == 120000
        assert int.from_bytes(inp.script_sig[:1], byteorder='little') == 3


class TestUtil(unittest.TestCase):
    def test_target_unpack(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_unpack(b"\x1d\x00\xff\xff"),
            0x00000000FFFF0000000000000000000000000000000000000000000000000000)

    def test_target_from_diff(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_from_diff(1),
            0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    def testb58(self):
        assert get_bcaddress_version('15VjRaDX9zpbA8LVnbrCAFzrVzN7ixHNsC') is 0
        _ohai = 'o hai'.encode('ascii')
        _tmp = b58encode(_ohai)
        assert _tmp == 'DYB3oMS'
        assert b58decode(_tmp, 5) == _ohai
