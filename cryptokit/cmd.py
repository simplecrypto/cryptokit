import argparse
import cryptokit.base58 as base58

from binascii import unhexlify, hexlify


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


    args = parser.parse_args()
    vals = vars(args)
    command = vals.pop('command')
    globals()[command](**vals)

if __name__ == '__main__':
    main()
