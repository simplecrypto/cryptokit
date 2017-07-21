import argparse
import importlib
import cryptokit.base58 as base58
import cryptokit.block as block
from cryptokit import target_unpack, uint256_from_str, uint256_to_str

from binascii import unhexlify, hexlify


def import_helper(dotted_path):
    module, cls = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module)
    return getattr(module, cls)


def algo_verify(block_hex, hash_function):
    block_bytes = unhexlify(block_hex)
    hash_func = import_helper(hash_function)
    block_hash = hash_func(block_bytes)
    block_hash_int = uint256_from_str(block_hash)
    bits = block_bytes[72:76][::-1]
    target = target_unpack(bits)
    print("Unpacked target of {}".format(hexlify(uint256_to_str(target))))
    print("Block hash is {}".format(hexlify(block_hash)))
    print("Block hash is valid? {}".format(block_hash_int <= target))


def address_version(address):
    print("Parsing address {}".format(address))
    try:
        version, address_bytes = base58._parse_address(address)
    except AttributeError:
        print("Invalid address checksum!")
    else:
        print("Address version: {}".format(version))
        print("Bytes address: {}".format(repr(address_bytes)))
        print("Hex address: {}".format(hexlify(address_bytes)))


def main():
    parser = argparse.ArgumentParser(description='Commandline utilities for cryptocurrencies')
    subparsers = parser.add_subparsers(dest='command')

    version = subparsers.add_parser('address_version', help='decode an address and display version')
    version.add_argument('address')

    algo_verify = subparsers.add_parser('algo_verify', help='tries to hash a block to verify hash algo correctness')
    algo_verify.add_argument('block_hex', help='a hex dump from the getblock rpc')
    algo_verify.add_argument('hash_function', help='a dotted module path to a function that can be imported. ex ltc_scrypt.getPoWHash')


    args = parser.parse_args()
    vals = vars(args)
    command = vals.pop('command')
    globals()[command](**vals)

if __name__ == '__main__':
    main()
