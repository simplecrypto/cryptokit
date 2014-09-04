import os
import socket
import hashlib
import logging
import bsddb3.db as bsddb

from .. import sha256d
from ..base58 import b58encode, b58decode
from ..bitcointools.deserialize import parse_BlockLocator
from ..bitcointools.BCDataStream import BCDataStream

logger = logging.getLogger(__name__)


class DecryptionError(Exception):
    pass


class ChecksumError(Exception):
    pass


class ParsingError(Exception):
    pass


def decode_base58_check(sec):
    vchRet = b58decode(sec, None)
    secret = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = sha256d(secret)
    cs32 = hash[0:4]
    if cs32 != csum:
        raise ChecksumError("Invalid checksum")

    return secret


def encode_base58_check(secret):
    hash = sha256d(secret)
    return b58encode(secret + hash[0:4])


def priv_key_to_secret(privkey):
    if len(privkey) == 279:
        return privkey[9:9+32]
    else:
        return privkey[8:8+32]


def parse_CAddress(vds):
    d = {'ip': None, 'port': None, 'nTime': None}
    try:
        d['nVersion'] = vds.read_int32()
        d['nTime'] = vds.read_uint32()
        d['nServices'] = vds.read_uint64()
        d['pchReserved'] = vds.read_bytes(12)
        d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
        d['port'] = vds.read_uint16()
    except Exception:
        logger.warn("Unable to properly parse CAddress!", exc_info=True)
    return d


def parse_setting(setting, vds):
    if setting[0] == "f":   # flag (boolean) settings
        return str(vds.read_boolean())
    elif setting[0:4] == "addr":  # CAddress
        d = parse_CAddress(vds)
        print d
        return "{ip}:{port}".format(**d)
    elif setting == "nTransactionFee":
        return vds.read_int64()
    elif setting == "nLimitProcessors":
        return vds.read_int32()
    return 'unknown setting'


def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def hash_160_to_bc_address(h160, version):
    vh160 = chr(version) + h160
    h = sha256d(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)


def inversetxid(txid):
    if len(txid) is not 64:
        print("Bad txid")
        return "CORRUPTEDTXID:"+txid
    new_txid = ""
    for i in range(32):
        new_txid += txid[62-2*i]
        new_txid += txid[62-2*i+1]
    return new_txid


class Wallet(object):

    default_db_flags = (
        bsddb.DB_THREAD
    )

    default_env_flags = (
        bsddb.DB_INIT_LOCK |
        bsddb.DB_INIT_LOG |
        bsddb.DB_INIT_MPOOL |
        bsddb.DB_INIT_TXN |
        bsddb.DB_THREAD
    )

    def __init__(self, version):
        self.addrtype = version

    def public_key_to_bc_address(self, public_key):
        h160 = hash_160(public_key)
        return hash_160_to_bc_address(h160, self.addrtype)

    def SecretToASecret(self, secret, compressed=False):
        prefix = chr((self.addrtype + 128) & 255)
        try:
            prefix = chr(128)
            vchIn = prefix + secret
            if compressed:
                vchIn += '\01'
            return encode_base58_check(vchIn)
        except Exception:
            raise ParsingError("Unable to convert secret")

    def ASecretToSecret(self, sec):
        vch = decode_base58_check(sec)
        prefix = (self.addrtype + 128) & 255
        if vch[0] != chr(prefix):
            logger.warn('Warning: adress prefix seems bad (%d vs %d)'
                        % (ord(vch[0]), prefix))
        return vch[1:]

    def read(self):
        data = {}
        data['keys'] = []
        data['pool'] = []
        data['tx'] = []
        data['names'] = {}
        data['ckey'] = []
        data['mkey'] = {}
        data['settings'] = {}

        for type, d in self._parse():
            if type == "tx":
                data['tx'].append(
                    {"tx_id": d['tx_id'],
                     "txin": d['txIn'],
                     "txout": d['txOut'],
                     "tx_v": d['txv'],
                     "tx_k": d['txk']})

            elif type == "name":
                data['names'][d['hash']] = d['name']

            elif type == "version":
                data['version'] = d['version']

            elif type == "minversion":
                data['minversion'] = d['minversion']

            elif type == "setting":
                data["settings"][d['setting']] = d['value']

            elif type == "defaultkey":
                data['defaultkey'] = self.public_key_to_bc_address(d['key'])

            elif type == "key":
                addr = self.public_key_to_bc_address(d['public_key'])
                compressed = d['public_key'][0] != '\04'
                sec = self.SecretToASecret(
                    priv_key_to_secret(d['private_key']), compressed)
                hexsec = self.ASecretToSecret(sec)[:32].encode('hex')
                data['keys'].append(
                    {'addr': addr,
                     'sec': sec,
                     'secret': hexsec,
                     'pubkey': d['public_key'].encode('hex'),
                     'compressed': compressed,
                     'private': d['private_key'].encode('hex')}
                )

            elif type == "wkey":
                if not data.has_key('wkey'):
                    data['wkey'] = []
                data['wkey']['created'] = d['created']

            elif type == "pool":
                try:
                    data['pool'].append(
                        {
                            'n': d['n'],
                            'addr': self.public_key_to_bc_address(
                                d['public_key']),
                            'addr2': self.public_key_to_bc_address(
                                d['public_key'].decode('hex')),
                            'addr3': self.public_key_to_bc_address(
                                d['public_key'].encode('hex')),
                            'nTime': d['nTime'],
                            'nVersion': d['nVersion'],
                            'public_key_hex': d['public_key']})
                except:
                    data['pool'].append(
                        {'n': d['n'],
                         'addr': self.public_key_to_bc_address(d['public_key']),
                         'nTime': d['nTime'],
                         'nVersion': d['nVersion'],
                         'public_key_hex': d['public_key'].encode('hex')})

            elif type == "acc":
                data['acc'] = d['account']
                print(
                    "Account %s (current key: %s)" %
                    (d['account'], self.public_key_to_bc_address(d['public_key'])))

            elif type == "acentry":
                data['acentry'] = (
                    d['account'],
                    d['nCreditDebit'],
                    d['otherAccount'],
                    d['nTime'],
                    d['n'],
                    d['comment'])

            elif type == "bestblock":
                data['bestblock'] = d['hashes'][0][::-1].encode('hex_codec')

            elif type == "ckey":
                data['crypted'] = True
                compressed = d['public_key'][0] != '\04'
                data['keys'].append(
                    {
                        'pubkey': d['public_key'].encode('hex'),
                        'addr': self.public_key_to_bc_address(
                            d['public_key']),
                        'encrypted_privkey': d['encrypted_private_key'].encode('hex_codec'),
                        'compressed': compressed})

            elif type == "mkey":
                data['mkey']['nID'] = d['nID']
                data['mkey']['encrypted_key'] = d[
                    'encrypted_key'].encode('hex_codec')
                data['mkey']['salt'] = d['salt'].encode('hex_codec')
                data['mkey']['nDerivationMethod'] = d['nDerivationMethod']
                data['mkey']['nDerivationIterations'] = d['nDerivationIterations']
                data['mkey']['otherParams'] = d['otherParams']

                if False:  # Disabled
                    res = crypter.SetKeyFromPassphrase(
                        passphrase,
                        d['salt'],
                        d['nDerivationIterations'],
                        d['nDerivationMethod'])
                    if res == 0:
                        logging.error("Unsupported derivation method")
                        sys.exit(1)
                    masterkey = crypter.Decrypt(d['encrypted_key'])
                    crypter.SetKey(masterkey)

            else:
                data[type] = 'unsupported'
                print "Wallet data not recognized: " + str(d)

        return data

    def _parse(self):
        kds = BCDataStream()
        vds = BCDataStream()

        def parse_TxIn(vds):
            return {
                'prevout_hash': vds.read_bytes(32).encode('hex'),
                'prevout_n': vds.read_uint32(),
                'scriptSig': vds.read_bytes(vds.read_compact_size()).encode('hex'),
                'sequence': vds.read_uint32()
            }

        def parse_TxOut(vds):
            return {
                'value': vds.read_int64() / 1e8,
                'scriptPubKey': vds.read_bytes(
                    vds.read_compact_size()).encode('hex')
            }

        cursor = self.db.cursor(flags=bsddb.DB_READ_COMMITTED)
        cursor_ret = cursor.first()
        while cursor_ret:
            key, value = cursor_ret

            d = {}

            kds.clear()
            kds.write(key)
            vds.clear()
            vds.write(value)

            type = kds.read_string()

            d["__key__"] = key
            d["__value__"] = value
            d["__type__"] = type

            try:
                if type == "tx":
                    d["tx_id"] = inversetxid(
                        kds.read_bytes(32).encode('hex_codec'))
                    start = vds.read_cursor
                    d['version'] = vds.read_int32()
                    n_vin = vds.read_compact_size()
                    d['txIn'] = []
                    for i in xrange(n_vin):
                        d['txIn'].append(parse_TxIn(vds))
                    n_vout = vds.read_compact_size()
                    d['txOut'] = []
                    for i in xrange(n_vout):
                        d['txOut'].append(parse_TxOut(vds))
                    d['lockTime'] = vds.read_uint32()
                    d['tx'] = vds.input[start:vds.read_cursor].encode('hex_codec')
                    d['txv'] = value.encode('hex_codec')
                    d['txk'] = key.encode('hex_codec')
                elif type == "name":
                    d['hash'] = kds.read_string()
                    d['name'] = vds.read_string()
                elif type == "version":
                    d['version'] = vds.read_uint32()
                elif type == "minversion":
                    d['minversion'] = vds.read_uint32()
                elif type == "setting":
                    d['setting'] = kds.read_string()
                    d['value'] = parse_setting(d['setting'], vds)
                elif type == "key":
                    d['public_key'] = kds.read_bytes(kds.read_compact_size())
                    d['private_key'] = vds.read_bytes(vds.read_compact_size())
                elif type == "wkey":
                    d['public_key'] = kds.read_bytes(kds.read_compact_size())
                    d['private_key'] = vds.read_bytes(vds.read_compact_size())
                    d['created'] = vds.read_int64()
                    d['expires'] = vds.read_int64()
                    d['comment'] = vds.read_string()
                elif type == "defaultkey":
                    d['key'] = vds.read_bytes(vds.read_compact_size())
                elif type == "pool":
                    d['n'] = kds.read_int64()
                    d['nVersion'] = vds.read_int32()
                    d['nTime'] = vds.read_int64()
                    d['public_key'] = vds.read_bytes(vds.read_compact_size())
                elif type == "acc":
                    d['account'] = kds.read_string()
                    d['nVersion'] = vds.read_int32()
                    d['public_key'] = vds.read_bytes(vds.read_compact_size())
                elif type == "acentry":
                    d['account'] = kds.read_string()
                    d['n'] = kds.read_uint64()
                    d['nVersion'] = vds.read_int32()
                    d['nCreditDebit'] = vds.read_int64()
                    d['nTime'] = vds.read_int64()
                    d['otherAccount'] = vds.read_string()
                    d['comment'] = vds.read_string()
                elif type == "bestblock":
                    d['nVersion'] = vds.read_int32()
                    d.update(parse_BlockLocator(vds))
                elif type == "ckey":
                    d['public_key'] = kds.read_bytes(kds.read_compact_size())
                    d['encrypted_private_key'] = vds.read_bytes(
                        vds.read_compact_size())
                elif type == "mkey":
                    d['nID'] = kds.read_uint32()
                    d['encrypted_key'] = vds.read_string()
                    d['salt'] = vds.read_string()
                    d['nDerivationMethod'] = vds.read_uint32()
                    d['nDerivationIterations'] = vds.read_uint32()
                    d['otherParams'] = vds.read_string()

                yield type, d

            except Exception:
                logger.error("Unable to parse wallet!", exc_info=True)
                logging.debug("key data: %s" % key)
                logging.debug("key data in hex: %s" % key.encode('hex_codec'))
                logging.debug("value data in hex: %s" % value.encode('hex_codec'))
                raise ParsingError("ERROR parsing wallet entry of type {}".format(type))

            cursor_ret = cursor.next()

    @classmethod
    def from_wallet_path(cls, path, version, writable=False,
                         create=False):
        path = os.path.abspath(os.path.expanduser(path))
        db_flags = cls.default_db_flags
        if writable is not True:
            db_flags |= bsddb.DB_RDONLY
        if create is True:
            db_flags |= bsddb.DB_CREATE
        else:
            assert os.path.isfile(path)

        obj = cls(version)
        obj.env = bsddb.DBEnv(0)
        path, filename = os.path.split(path)
        obj.env.open(path, cls.default_env_flags)
        obj.db = bsddb.DB(obj.env)
        obj.db.open(filename, "main", bsddb.DB_BTREE, db_flags)
        return obj
