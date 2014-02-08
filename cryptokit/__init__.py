from struct import pack, unpack


class BitcoinEncoding(object):

    def varlen_decode(self, byte_string):
        """ Unpacks the variable count bytes present in several bitcoin
        objects. First byte signals overall length of and then byte lengths are
        reads accordingly. """
        if byte_string[0] == 0xff:
            return self.unpack('<Q', byte_string[1:9]), byte_string[9:]
        if byte_string[0] == 0xfe:
            return self.unpack('<L', byte_string[1:5]), byte_string[5:]
        if byte_string[0] == 0xfd:
            return self.funpack('<H', byte_string[1:3]), byte_string[3:]
        return byte_string[0], byte_string[1:]

    def varlen_encode(self, number):
        """ This is the inverse of the above function, accepting a count and
        encoding that count """
        if number < 0xfd:
            return pack('<B', number)
        if number <= 0xffff:
            return b'\xfd' + pack('<H', number)
        if number <= 0xffffffff:
            return b'\xfe' + pack('<L', number)
        return b'\xff' + pack('<Q', number)

    def funpack(self, *args, **kwargs):
        """ Helper for the common act of unpacking a single item """
        return unpack(*args, **kwargs)[0]
