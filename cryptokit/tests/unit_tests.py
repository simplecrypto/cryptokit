from __future__ import unicode_literals
from future.builtins import int

import unittest
from cryptokit.base58 import get_bcaddress_version, b58encode, b58decode
from cryptokit.transaction import Input, Transaction, Output
import cryptokit.bitcoin.data as bitcoin_data
from cryptokit.block import BlockTemplate, from_merklebranch, merklebranch, merkleroot
from cryptokit import (target_unpack, target_from_diff, Hash, uint256_from_str,
                       bits_to_difficulty, bits_to_shares, reverse_hash)

from binascii import unhexlify, hexlify
from pprint import pprint
from struct import pack
from hashlib import sha256

class TestBlockTemplate(unittest.TestCase):
    def test_block_header2(self):
        # pulled from litecoin blockchain and modded slightly with full block header
	block_data = {
	    "hash" : "0000051b2ce4cc300257d68a10f96d30f5e01088a64c837f803e871e5abc8d9a",
	    "height" : 2,
	    "version" : 1,
	    "merkleroot" : "a37b1d53207b8dc4d94bc6e3171247043743ad7459b09bc0f6127e5d29c13d81",
	    "coinbasevalue" : 6000000,
	    "curtime" : 1420477153,
	    "nonce" : hexlify(pack(str(">L"), 3087073600)),
	    "bits" : "1e0fffff",
	    "previousblockhash" : "00000b24e3b3f52901eaa73da7cd29ce310e46f1f11f0c54a23babd5fe545476",
	    "flags" : "proof-of-work stake-modifier",
	    "proofhash" : "0000051b2ce4cc300257d68a10f96d30f5e01088a64c837f803e871e5abc8d9a",
	    "tx" : [
	        ("a37b1d53207b8dc4d94bc6e3171247043743ad7459b09bc0f6127e5d29c13d81", "01000000e1c2aa54010000000000000000000000000000000000000000000000000000000000000000ffffffff03520104ffffffff010080dd62b22102001976a914a3ada1c4a249ab14d63e4d881c5ae36ed0f7025088ac00000000"),

	    ]
	}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True, pos=True)
                        for _, data in block_data['tx']]
	print(transactions)
        self.assertEquals(hexlify(merkleroot(transactions, be=True)[0]), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.lehexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        tmplt = BlockTemplate.from_gbt(block_data, coinbase, transactions=transactions, pos=True)
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)),
                          block_data['merkleroot'])
	pprint(tmplt.raw_block(block_data['nonce'], b'', b'', pos=True))
	pprint(block_data)
        header = tmplt.block_header(block_data['nonce'], b'', b'', pos=True)	
        target = target_unpack(unhexlify(block_data['bits']))
	hash = self.hash("scrypt", header)
	print("Hash: {0}, Target: {1}".format(hash, target))
        assert hash < target

    def hash(self, algo, dat):
        if algo == "scrypt":
            from ltc_scrypt import getPoWHash
            hsh = getPoWHash(dat)
	elif algo == "sha256":
	    hsh = sha256(sha256(dat).digest()).digest()
        return uint256_from_str(hsh)

if __name__ == "__main__":
   unittest.main()
