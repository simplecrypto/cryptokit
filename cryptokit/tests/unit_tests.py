import unittest

from cryptokit.block_header import Hash
from hashlib import sha256


class TestHashTuple(unittest.TestCase):
    def test_hash_hex(self):
        hsh = Hash.from_be_hex(
            "c8a78165527ab2022a57b095fef86c83e472b7d639cc246c3b40623c374fed4d")
        self.assertEquals("d4def473c32604b3c642cc936d7b274e38c68fef590b75a2202ba72556187a8c", hsh.le_hex)
        self.assertEquals("8c7a185625a72b20a2750b59ef8fc6384e277b6d93cc42c6b30426c373f4ded4", hsh.be_hex)
