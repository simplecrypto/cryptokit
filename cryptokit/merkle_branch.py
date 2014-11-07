import struct

from . import BitcoinEncoding, Hash, parse_bc_int, stream_bc_int, sha256d


class MerkleBranch(BitcoinEncoding):
    """ An object representation of a merkle branch. Specification here:
    https://en.bitcoin.it/wiki/Merged_mining_specification#Merkle_Branch
    """
    def __init__(self):
        self.branch_hashes = []
        self.branch_side_mask = 0

    @classmethod
    def from_stream(cls, f):
        self = cls()
        branch_length = parse_bc_int(f)
        for i in range(branch_length):
            self.branch_hashes.append(Hash.from_le(f.read(32)))
        self.branch_side_mask = struct.unpack("<L")
        return self

    def to_stream(self, f):
        f.write(stream_bc_int(len(self.branch_hashes)))
        for hsh in self.branch_hashes:
            f.write(hsh.le)
        f.write(struct.pack("<L", self.branch_side_mask))

    @classmethod
    def from_hashes(self, hashes, index):
        hash_list = [(lambda _h=h: _h, i == index, []) for i, h in enumerate(hashes)]

        while len(hash_list) > 1:
            hash_list = [
                (
                    lambda _left=left, _right=right: hash256d(
                        merkle_record_type.pack(dict(left=_left(), right=_right()))),
                    left_f or right_f,
                    (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
                )
                for (left, left_f, left_l), (right, right_f, right_l) in
                zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
            ]

        res = [x['hash']() for x in hash_list[0][2]]

        assert hash_list[0][1]
        assert index == sum(k*2**i for i, k in enumerate([1-x['side'] for x in hash_list[0][2]]))

        return dict(branch=res, index=index)
