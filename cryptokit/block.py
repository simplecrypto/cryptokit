from __future__ import unicode_literals
from future.builtins import bytes, range, chr
from future import standard_library
standard_library.install_hooks()

from hashlib import sha256
from itertools import tee, islice, zip_longest
from binascii import unhexlify, hexlify
from sys import byteorder
from struct import pack

from . import BitcoinEncoding, target_unpack
from .transaction import Transaction


def pairwise(iterator):
    """ Returns pairs of items until none are left in either iterator. If the
    list is odd and the second iterator runs out None will be returned for
    second arg """
    a, b = tee(iterator)
    return zip_longest(islice(a, 0, None, 2), islice(b, 1, None, 2))


def merkleroot(iterator, be=False, hashes=False):
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


def merklebranch(iterator, be=False, hashes=False):
    """ Similar to the above method, this instead generates a merkle branch
    for mining clients to quickly re-calculate the merkle root with minimum
    of re-hashes while chaning the coinbase extranonce. Big endian by default,
    change kwarg for little endian """
    def shamaster(h1, h2):
        if h1 is None:
            return None
        hsh = sha256(sha256(h1 + (h2 or h1)).digest()).digest()
        # encode little endian
        if byteorder == 'big':
            return hsh[::-1]
        return hsh

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
            branch.append(h_list[1][::-1])
        else:
            branch.append(h_list[1])
        h_list = [shamaster(h1, h2) for h1, h2 in pairwise(h_list)]
    return branch


def from_merklebranch(branch_list, coinbase, be=False):
    """ Computes a merkle root from a branch_list and a coinbase hash. Assumes
    branch_list is a list of little endian byte arrays of hash values, as is
    returned by merklebranch by default. Coinbase is expected to be a
    Transaction object. """
    root = coinbase.lehash
    for node in branch_list:
        root = sha256(sha256(root + node).digest()).digest()

    # reverse order to le if sys is be
    if byteorder == 'big' and len(branch_list) > 0:
        root = root[::-1]

    # return be if requested
    if be:
        return root[::-1]
    return root


class BlockTemplate(BitcoinEncoding):
    """ An object for encapsulating common block header/template type actions. """
    def __init__(self, raw=None):
        # little endian hex format, as given by most rpc calls
        self.hash_prev = None  # bytes
        # hex string
        self.ntime = None
        # target as compressed hex
        self.target = None
        # integer version
        self.version = 2
        # assumes that the extranonces are missing and will be passed for
        # validation
        self.coinbase1 = None
        self.coinbase2 = None
        # expects a list of Transaction objects...
        self.transactions = None
        self._merklebranch = None

    @classmethod
    def from_gbt(cls, retval, coinbase, extra_length=0, transactions=None):
        """ Creates a block template object from a get block template call
        and a coinbase transaction object. extra_length needs to be the length
        of padding that was added for extranonces (both 1 and 2 if added).
        Transactions should be a list of Transaction objects that will be
        put into the block. """
        if transactions is None:
            transactions = []
        coinbase1, coinbase2 = coinbase.assemble(split=True)
        inst = cls()
        inst.hash_prev = retval['previousblockhash']
        inst.ntime = hexlify(pack(str("<L"), retval['curtime']))
        inst.target = retval['target']
        inst.version = retval['version']
        inst.coinbase1 = coinbase1[:-1 * extra_length]
        inst.coinbase2 = coinbase2
        inst.transactions = transactions
        return inst

    @property
    def merklebranch(self):
        if self._merklebranch is None:
            self._merklebranch = merklebranch(self.transactions)
        return self._merklebranch

    @property
    def merklebranch_hex(self):
        return [hexlify(hsh) for hsh in self.merklebranch]

    @property
    def target_int(self):
        return target_unpack(self.target)

    @property
    def version_packed(self):
        return pack(str("<L"), self.version)

    @property
    def nbits_packed(self):
        return pack(str("<L"), self.nbits)

    @property
    def ntime_packed(self):
        return pack(str("<L"), self.ntime)

    def merkleroot(self, coinbase):
        """ Accepts coinbase transaction object and returns what the merkleroot
        would be for this template """
        return from_merklebranch(self.merklebranch, coinbase)

    def block_header(self, nonce, extra1, extra2):
        """ Builds a block header given nonces and extranonces. Assumes extra1
        and extra2 are bytes of the proper length from when the coinbase
        fragments were originally generated. Assumes nonce is just an integer
        since it's always 4 bytes wide. """
        # calculate the merkle root by assembling the coinbase transaction
        coinbase = unhexlify(self.coinbase1) + extra1 + extra2
        coinbase += unhexlify(self.coinbase2)
        coinbase = Transaction(coinbase)
        header = bytes(pack(str("<L"), self.version))
        header += unhexlify(self.hash_prev)
        header += self.merkleroot(self.merklebranch, coinbase)
        header += bytes(pack(str("<L"), self.ntime))
        header += bytes(pack(str("<L"), self.target))
        header += bytes(pack(str("<L"), nonce))
        return header

    @classmethod
    def validate_scrypt(cls, block_header, target=None):
        """ Hashes a block header with scrypt to confirm if it meets a target
        requirement or not """
        from ltc_scrypt import getPoWHash
        # builds a block header from the template and confirms a difficulty
        hsh = getPoWHash(block_header)
        print(hexlify(hsh[::-1]))
        return int(hexlify(hsh[::-1]), 16) < target
