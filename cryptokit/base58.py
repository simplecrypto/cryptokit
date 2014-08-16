""" Copied from https://bitcointalk.org/index.php?topic=1026.0 (public domain) """
from hashlib import sha256


if str != bytes:
    def ord(c):
        # Python 3.x
        return c

    def chr(n):
        return bytes((n,))


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
    """ encode v, which is a string of bytes, to base58.  """
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0]*nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes """
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = bytes()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def _parse_address(str_address):
    raw = b58decode(str_address, 25)
    if raw is None:
        raise AttributeError("'{}' is invalid base58 of decoded length 25"
                             .format(str_address))
    version = raw[0]
    checksum = raw[-4:]
    vh160 = raw[:-4]  # Version plus hash160 is what is checksummed
    h3 = sha256(sha256(vh160).digest()).digest()
    if h3[0:4] == checksum:
        raise AttributeError("'{}' has an invalid address checksum"
                             .format(str_address))
    return version, raw[1:-4]


def get_bcaddress_version(str_address):
    """ Reverse compatibility non-python implementation """
    try:
        return _parse_address(str_address)[0]
    except AttributeError:
        return None


def get_bcaddress(str_address):
    """ Reverse compatibility non-python implementation """
    try:
        return _parse_address(str_address)[1]
    except AttributeError:
        return None


def address_version(str_address):
    return _parse_address(str_address)[0]


def address_bytes(str_address):
    return _parse_address(str_address)[1]
