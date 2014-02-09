""" An assortment of fuzz tests that use real network data to test various
structures in this package. They generally use bitcoind to collect data and
confirm that different methods work properly. """
from __future__ import unicode_literals
from bitcoinrpc.proxy import AuthServiceProxy
from cryptokit.transaction import Transaction
from cryptokit.block import merkleroot, merklebranch
from binascii import unhexlify, hexlify
from hashlib import sha256
from time import sleep
from pprint import pprint

import six
import argparse
import sys


def transaction_fuzz(args):
    """ Requests pending transactions from bitcoind and parses them with the
    transaction object disassemble. Uses the input hashes of these to look up
    more transactions and records and prints any failures. """
    conn = AuthServiceProxy("http://{0}:{1}@{2}:{3}/".format(args.username,
                                                             args.password,
                                                             args.address,
                                                             args.port))
    failure = 0
    success = 0
    coinbase = 0
    proc = set()
    fail = []
    unidentified = {}
    try:
        while True:
            # get new transactions from bitcoind
            trans = conn.getblocktemplate()['transactions']
            unidentified.update(
                {val['hash']: val['data'] for val in trans if val['hash'] not in proc})
            new = {}
            for hash, data in six.iteritems(unidentified):
                print("Testing transaction " + hash)
                t_obj = Transaction(unhexlify(data))
                for inp in t_obj.inputs:
                    new_hash = hexlify(inp.prevout_hash[::-1]).decode('ascii')
                    if new_hash not in proc:
                        try:
                            new[new_hash] = conn.getrawtransaction(new_hash)
                        except Exception:
                            pass
                t_obj.assemble()
                if t_obj.is_coinbase:
                    coinbase += 1
                t_obj.disassemble(t_obj._raw)
                try:
                    assert t_obj.lehexhash.decode('ascii') == hash
                except Exception:
                    failure += 1
                    fail.append(data)
                else:
                    success += 1

                proc.add(hash)

            unidentified.update(new)
            sys.stdout.write(".")
            sleep(args.sleep)
    finally:
        print()
        for f in fail:
            print("\n\n")
            print(f)
        print("Failed: %s" % failure)
        print("Coinbase: %s" % coinbase)
        print("Success: %s" % success)


def merkleroot_fuzz(args):
    """ Tests the merkleroot and merklebranch functions by getting a block
    from a bitcoind server and recalculating the merkle root from the given
    transaction hashes. Checks against bitcoind's merkleroot listed. """
    conn = AuthServiceProxy("http://{0}:{1}@{2}:{3}/".format(args.username,
                                                             args.password,
                                                             args.address,
                                                             args.port))
    branch_failure = 0
    root_failure = 0
    iters = 0
    fail = []
    blocks = conn.getblockcount()
    try:
        for i in range(30000, blocks):
            block = conn.getblock(conn.getblockhash(i))
            deserial = [unhexlify(hsh)[::-1] for hsh in block['tx']]
            # compute the merkle root to confirm
            root = hexlify(merkleroot(deserial, hashes=True, be=False)[0]).decode('ascii')
            # now compute the merkle root from a branch by pretending the first
            # transaction was a coinbase
            if len(block['tx']) > 1:
                merkle = deserial[0]
                for hsh in merklebranch(deserial[1:], hashes=True):
                    merkle = sha256(sha256(merkle + hsh).digest()).digest()
                merkle = hexlify(merkle[::-1]).decode('ascii')

                if merkle != block['merkleroot']:
                    branch_failure += 1
                    print("FAIL BRANCH\n")
                    fail.append(block)

            print("COMP: " + block['merkleroot'] + " " + str(len(block['tx'])))
            if root != block['merkleroot']:
                root_failure += 1
                print("FAIL ROOT\n")
                fail.append(block)

            iters += 1
            sleep(args.sleep)
    finally:
        for f in fail:
            print(f)
        print()
        print("Branch Failed: %s" % branch_failure)
        print("Root Failed: %s" % root_failure)
        print("Iterations: %s" % iters)


if __name__ == "__main__":
    methods = {'transaction': transaction_fuzz,
               'merkleroot': merkleroot_fuzz}
    parser = argparse.ArgumentParser(
        description='Test transactions by connecting to memory pool')
    parser.add_argument('username', help='rpc username')
    parser.add_argument('password', help='rpc password')
    parser.add_argument('-m', '--method', default='transaction',
                        help='the testing method to run')
    parser.add_argument('-p', '--port', default=18332,
                        help='rpc port, default to testnet')
    parser.add_argument('-a', '--address', default='localhost',
                        help='address to connect to')
    parser.add_argument('-s', '--sleep', default=1, type=float,
                        help='time to wait between pings to client')
    args = parser.parse_args()

    methods[args.method](args)
