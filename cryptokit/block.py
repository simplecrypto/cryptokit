from hashlib import sha256
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest
from itertools import tee, islice
from binascii import unhexlify, hexlify
from collections import namedtuple

from . import BitcoinEncoding


def pairwise(iterator):
    """ Returns pairs of items until none are left in either iterator. If the
    list is odd and the second iterator runs out None will be returned for
    second arg """
    a, b = tee(iterator)
    return zip_longest(islice(a, 0, None, 2), islice(b, 1, None, 2))


def merkleroot(iterator, be=True, hashes=False):
    """ When given an iterator producing Transaction objects or transaction
    hashes (set hash=True, send in big endian) this computes a MerkleRoot for
    the collection of transactions. Returned as big endian byte string by
    default with second parameter as size of iterator. Could be optimized to
    use the list in place, but thats a future job... """
    # get the hashes of all the transactions
    if not hashes:
        h_list = [t.hash for t in iterator]
    else:
        h_list = iterator

    size = len(h_list)
    # build our tree by repeated halving of the list
    while len(h_list) > 1:
        h_list = [sha256(sha256(h1 + (h2 or h1)).digest()).digest()
                  for h1, h2 in pairwise(h_list)]
    # return little endian
    if be:
        return h_list[0], size
    return h_list[0][::-1], size


def merklebranch(iterator, be=True, hashes=False):
    """ Similar to the above method, this instead generates a merkle branch
    for mining clients to quickly re-calculate the merkle root with minimum
    of re-hashes while chaning the coinbase extranonce. Big endian by default,
    change kwarg for little endian """
    def shamaster(h1, h2):
        if h1 is None:
            return None
        return sha256(sha256(h1 + (h2 or h1)).digest()).digest()
    # put a placeholder in our level zero that pretends to be the coinbase
    if not hashes:
        h_list = [None] + [t.hash for t in iterator]
    else:
        h_list = [None] + list(iterator)
    branch = []
    # build each level of the tree and pull out the leftmost non-None
    while len(h_list) > 1:
        # left most is what will be recomputed, we want the one right of the
        # leftmost
        if be:
            branch.append(h_list[1])
        else:
            branch.append(h_list[1][::-1])
        h_list = [shamaster(h1, h2) for h1, h2 in pairwise(h_list)]
    return branch


class BlockHeader(BitcoinEncoding):
    """ An object that wraps a block header. Still WIP. """
    def __init__(self, raw=None):
        # raw block header data in byte format
        self._raw = raw
        # little endian byte format
        self.hash_prev = None  # bytes
        self.merkleroot = None  # bytes
        self.time = 0
        self.version = 1
        if raw:
            self.disassemble()
        else:
            self._hash = None
