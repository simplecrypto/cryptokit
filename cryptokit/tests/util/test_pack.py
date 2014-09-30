# The following code is a derivative work of the code from the p2pool project,
# which is licensed GPLv3. This code therefore is also licensed under the terms
# of the GNU Public License, verison 3.
import unittest

from cryptokit.util import pack


class Test(unittest.TestCase):
    def test_VarInt(self):
        t = pack.VarIntType()
        for i in xrange(2**20):
            assert t.unpack(t.pack(i)) == i
        for i in xrange(2**36, 2**36+25):
            assert t.unpack(t.pack(i)) == i
