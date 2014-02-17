from __future__ import unicode_literals
from future.builtins import bytes, range

import unittest

from cryptokit.base58 import get_bcaddress_version, b58encode, b58decode
from cryptokit.transaction import Input, Transaction, Output
from cryptokit.block import BlockTemplate, from_merklebranch, merklebranch, merkleroot, scrypt
from cryptokit import target_unpack, target_from_diff, Hash, uint256_from_str, uint256_from_str_be

from hashlib import sha256
from binascii import unhexlify, hexlify
from pprint import pprint
from struct import pack


class TestHashTuple(unittest.TestCase):
    def test_hash_hex(self):
        hsh = Hash.from_be_hex(
            "c8a78165527ab2022a57b095fef86c83e472b7d639cc246c3b40623c374fed4d")
        self.assertEquals(
            "d4def473c32604b3c642cc936d7b274e38c68fef590b75a2202ba72556187a8c",
            hsh.le_hex)
        self.assertEquals(
            "8c7a185625a72b20a2750b59ef8fc6384e277b6d93cc42c6b30426c373f4ded4",
            hsh.be_hex)


class TestMerkleRoot(unittest.TestCase):
    def test_from_merkle(self):
        hashes = [
            u'031b96acd2c05833758460d46466be1086361cd9c2844f26538e0bf9afa19841',
            u'b20c1a5e2b69bac036596e3303fda56221f7a0890898512c06755399d63583c9',
            u'49ec27da3cc56167b01118461d22297e56654ab680d3ff5842263e0e35cff209',
            u'7cee60dcb944a00c2e1dda02774fdbe91dd4e920e12053f9b7b8d1e5fb539991',
            u'650a54d0b53cc89be342a3883b96462bcdb0054e6ec2c29c6fe81d08c0c2b546',
            u'10d44ef68e5f7929e2a79c42a83d5c4155fcf82da0901d3bdea436ba1da21cac',
            u'2a5c3ede2786638db6eb52a6229a828f0e7de3a33e1091d5caa1048592e05133',
            u'aff21bcae129d57dc37aa8c75d41652e5d7bd8a58bfd2195ad4e3e129b856e12',
            u'94ed6c0089a259b0fd593ff26a5055157179cc0679ae4f16f25c030b5a64b441',
            u'3effb59479c79f1cbe79e2bcb5825c3ec4b1c9fd2011ac121b1369d38234c4cc',
            u'98db3cccb6e2c6fd69d87693def5df9fc0720f7298fa811a523d7dfe42b5ae8f',
            u'3663378ea537dced269957442d17aa5452060c8b04a9b1b80613e496b8999a65',
            u'2ee24381fb4f3e52d0aabc1686096efbb1d5a0b63f0c7451f697d31fec34ac23',
            u'329439f7481c3efaff5e82936f650c063a797265f3b0941e5d20b5d0df930954',
            u'3da1168feef4a45c19cfac6cbe104927954a459a2010a0d3a5cc667087c5bf7c',
            u'c33e8ec70c0fee9e3794e91100987c22e7e1d96c32be10c93eb1e41ae2041136',
            u'80a39c4002c89f037f2bfdf9377027e8af0e302a709abc83a0312f541b37a5b8',
            u'3f979f56f041eb972b73cee4b992262d6c5dcf540bbb7804455c4c407fc6facf',
            u'11c7f9d16c7ca6ad5afac4308dcacdf8fd83aad23581d3a5a11311845465defa',
            u'9a9e3ed8aa8e72f8cf438e00f0d441e3ff7efc3ea5f4d8e8c199f142f46bd24d',
            u'1eb8a910da4c04f165fc222edaa840d1cd9ff4df4ecadbeb71fde0292b5dda44',
            u'95a9d16ce095f35da8c193afb411ae1dd0c4c6b9ea29b54b30b44bd7619b0f93',
            u'16097a77cf25ccb91a1b49f76869c288dc0f41535d38bef3ba5ab9f509beadaf',
            u'a847e20fb6de61346d2066dbaaf5e180355b64fbeac366a4c6c3a273d87ad6d2',
            u'c03678582368d04386a7d1dd568784ab6f16e7f9d99052b740e67103f77cf7d9',
            u'd3c0efa5b704ac115ce5e9bd6e60179e601a64711cb963e602daff93c94ab7eb',
            u'ea1355acd68536b8694cd143d7ca0a79caf6fde35c45178868ea38062ceb06f7',
            u'63de6020f5b7f80e446551cda8976e394ba834a8e1e083df32f440cba4cfa549',
            u'c6993904f9ad9fd4ba3fad6f1c94aba2f2c01ff889b5089bde976940554cde7a',
            u'8fafd793e9384fe5c88322ea47d01329f3b7f10c57e617088fd8b08bbe3f2919',
            u'2fc314299a442e27e53afcb4c511f8843cd81a29f363b18120db55eddc75b115',
            u'07cbb85877cb6c4e8dc137803f02667553031798bbe85709aaaaa7abc7d01cf9',
            u'75ecf3a3cf703c1909ec454e3059daff5c445aab8ea9e3b2f42fdf328124d5fb',
            u'd22b413f85483218c1225d4a2f5d5285b19095251445f2093370d447c8858568',
            u'ca555b2828aa24fe71a60c0b1042d9bf4827c9bdf2d791c3e2206f6b236f8b2c',
            u'e139729ba444a99d192ebf45b229f901e8ea29fb198143378467c2567fad8a38',
            u'8b8a08193e8675943f9f65dec0acffac7a648fedd90b80419a5d347d83999681',
            u'a9ffe21ec4c6a9f68fd48c753965896684fd03a5191996921d17b3543a08d69e',
            u'571ec571305ba5243a68b297c16ecb71add209ce4fa672c1ffdc90e969afd207',
            u'db37d10ed2449c7e223a3ce1346ed66a07b733fc0cdb8f9a27552b29dc61076c',
            u'bd3378261297648c09345fe7702a4028b2c56f853086eaea5e03cda2d1d6573e',
            u'71d0597baa6b673a1bac8daf5c9d2447bd64fba799449c5c8ec245b5d681cf5f',
            u'68d7ca294bbfe075f7dcc521db418fcb822bc86caaa96219d2e135258676aabd',
            u'dfef23ff7a3f21a946b2726ee88ed81e110be7152885d9a26996e7ba6b219e23',
            u'0e7ae7690568de29d763bc2e51f28e6767b431ffc83e223187111872a48ba598',
            u'd88a17b6325671243edfa315889be93828975c8a89ba2fea3f9e1754c874af3a',
            u'b01a28e8dd891aa6915ce5b2be55133b7177eec60cd97861a8aae93f4d4a79b0',
            u'691a7c91dd49578e363c2aa72c54248bb9e8389ca98c896950781390877c3a72',
            u'b9db62c767249d58ec70c18250482f0cd276d085ac4f7d07af095218cbc31448',
            u'c7b98e339ac1e47fcabf6c403974df3ed95c66134e867b350d835f64b7c24767',
            u'5839cb48d43dbbfa3aedded2a4936b2555325a7333e15cdbe4441350fdedc9ea',
            u'6b83bf5a2189cba5cf0e575b7d48268c4fc0ba96ca72043eceb0a20282b0d3f0',
            u'5347aa403cee27080fce61de817f6ea4f6521f2372756b7e3f798e37791f3a8b',
            u'2c9cce8b51f7e4fa2999eb9b7edd947dc085ffde88bbbd28df5ae0ccd1da1885',
            u'1121858dab0210eb61bee7e1cad801c2d91f81c1dce7db1791da44137ae0dd4c',
            u'8b4f50d0d80b707374d2c00a9278357edc040039d6987673df1722140201df05',
            u'b08f1f3c9fd02fa6d913027da36252885645c055099c0ca469e58c50806f337a',
            u'611a221b0682c6637cc540850e765cd3934719a224b60978a2592e48bc8dc5c2',
            u'c454503fdb63dce12b5be7762f22a2a57f3ec98eead60b85d22296a036bcbb56',
            u'5fee11f3e4459e95dbaaccd4e94c1ab682cbdaa20c2c8f59bccb429c2bc78ab1',
            u'09da229c7f1293acf84be8f878b92a588e5453f0245348f37bdc4d6f5a387d47',
            u'ed673ca00a18cde535fc81979e837098c73cdeee9c0ba19b58e4aeb81b165e2e',
            u'a25bf0b994f409d6d2a84f7d10af5989afe333bcfafc334db345083a7c86537c',
            u'643154069912d9df3c3db3fe968b71834efb9e2bdc38302ce13ba195d9694d82',
            u'ca8e9f9986bdcb6a0ff64082c2d3793ce3daf59174504b5c9072fc1fc2738087',
            u'6f243acbd348929cbe53b96354b1c79c326c08404b5dc4175eb7bb48cfe2eeb9',
            u'ba8c01b123c8cee5a9227a3ff9415c004180659e4766078902024ceb845aeac4',
            u'be082bb1b18d34d3b4cfbb05b96f638667a36d19e76397b23ae57460b3f57b31',
            u'01c984db15cc087990d2e84bc64686a9a99192ea1836abdb1be99c66f670eb15',
            u'583d5846f8f6b737c36554e63960fe74137cd9fd38294d59cfdf71e481a9e43f',
            u'a5a07cc3d98ab71a426764b7450f3f7d305051e392f3e432691550b15c30f6b1',
            u'e326d992a88c802cb28a77d25c6cc1d5d242cf01560f73c04f94133c9b73c769',
            u'c861a51d2cd70e181d1c8b3d8a4c20aa189934bae9c9a5621361c41132cb7f63',
            u'ce57dd89677933fbd2a2d19f652e1bb5ca61ad93bba9cd9ce465797498e6b0d4',
            u'118c4e00531ccd12b174471cf6e1cf30e972060011333596568ba35a01659a88',
            u'e7b446a4943c38b5cc88b94d1dd969044fb039da6825508a3293625cae0e92fc',
            u'44eb9324dc78179262b75a8f17e7d911c8e1c9910b48fccc84702894d37a5a44',
            u'3514ed8de21f8dbdd99b14d0af61414686db9860e4577af88d1e72955a028c47',
            u'60581a61184fcc6325914741507516ef7bc0d2bf217d6fa1d5fa3a755de75e47',
            u'ec4e485a2e1a0b846ea7deff79a2c0321f9c6b09f532cc526ca3d1c92977018c',
            u'0b33c756479df9cd2c0c7485413abaff4a7a33d7906d3509554525e33f593427',
            u'0d2221a6e35ab3f6c60bae81f55077311937f88ad59c3f2151f7d9edbfa7904e',
            u'8136819af4de83099aea5f8a67e0eeea58d0b7bceea3d2fbaf8ba1b0a58c52e0',
            u'aa95fc62ed225d0ac2576f699aef9100ae8baa667463a18bd5f4be18ef0a5ef3',
            u'6f6f6b4e9a01c6deb8c5a04677b9ff876cfbf76ec7fe4c3dedb87ce505e040c7',
            u'794ff1e55ac33d25d80d69a8c737c0b8b08a2dbfc814ae8156d5fb6a42e120f1',
            u'3305fb31f4c2e6de8fa6cc70becd6cc743ec225088fd4f10620e95d3bb646bb5',
            u'0cb57364c30d129add699c2b03d8369d703368c5f2fb2cc31b32058acebc0c7b',
            u'7e070ab3ffeddd00c7724d973209574ec9a3ee9858e1779f05044106b2da3899',
            u'60ddb151003083cc35a581714ccee94d429322bd1ad6b6584f4b14b2cf752d4c',
            u'7c5bc4b07705e7edaf25eb2aa9951a90990ceda10819a86432d765bcdf942633',
            u'a1eac1226c8f579048435e6b1f59818129780d0cbe9785a4a2fe8d3a7a18519b',
            u'889cf865c6567e25d5f9e0a73f44b52f34e4cc7afe561a53ee8a8a03b36069e3',
            u'b580bf1409c69899adaa5bb9808670a52e3f06c3d46c4a727c38a142ba964297',
            u'41215eaf44bca7469fba8647c8db3b96a6b98108daae266547340dcc496bd54c',
            u'0fb42e25504f215d7d23f4fb7cb1cbe11ca80d6ed3934171fe68e8b0bf478fd8',
            u'51e78675d2af5b5c4b9caf99d814dbac939788990a22144e7b4a6e22cc81007b',
            u'd703f3a9712395594b98c235a6749032c26a7cf4ecaf3f6d583b27cc6fa9dec4',
            u'8eb479a334b4a1be45c7bbb1327d6bf673d61903cced730c6ecc198951587df1',
            u'292c1a76011a0dc8a7628c746a5edfeb3e78287d1db019f71dd780dbaf4befd8',
            u'60f9d2e16962e7136a7ead6418af4cf053e961828bc8acc001af3bb59fbeca34',
            u'bebbd5d4b05824101343ef88bd98b31db5ae9d7298ef428dae2da799a022993e',
            u'a1f7d2f4b222f425546edb7ac729b5833c994b74cf029bf0ae1226174cf776d3',
            u'ea339fb2e68872d676f4c2e1295542f22ede06c040edeeb0916bfee4d19fcf46',
            u'db24ec449bcd05757bb38bae23dbc1353f6b1872dc4cc5c90c9d3afee40d8f82',
            u'f851bc47b636abdfd41eb4117d3eee8f209515f4cb23e8196c49619cc8ca83a7',
            u'350b40fca68801518a811460c2e5563cc0f87ac83cea5037711ee8602105ef15',
            u'4b5865a0b2a9c3caa84842a65d43690eba1023f01d4c812a77802e621c4be28a',
            u'672ff658e5c8466945a99e2de0345683eb00a0e36dd62703582a373fde780b50',
            u'ec79627d162ea984ed57c62e69ccb2b35f4c150759884e696fafacf54437febd',
            u'fbedb24e52d3297de748c099cba26d478692feede176b188cbf9e0db166e1c0c',
            u'bd71b1d3458bfa57458351b60d537f87ec5b7212c11f3e06783423480be7ebe5',
            u'0eefe2bb2844ad5f9f6af69799005b2fb75a0b79b7173387ae49c7959157208b',
            u'789d5e59e0817bbda57f8c0e2e5430cc67356b6ded07911b495ae9571d1bf872',
            u'c95bae84aa5c60ccb2dbc1c2f9eb5ee3099588cc41dda38ea322d03ff732c9cb',
            u'194a97f6afa0023a83f6294b6486a35fbe1e33ed66bc405d2884cc0daee44249',
            u'3a7c2ef8906eeb800d03e63c3fd912b47fa68c17d38949bddce6b1fb934592e9',
            u'e7cc8c6fe4a64b88834883e58dc076f4c3de251ba7d9d29c6f6b476f5b05148e',
            u'cdedb1d2d39f2bd56c937084766a3ce6b0a50242041c98f79bc06116ccced7d7',
            u'1be2ee4faf38b19c2e31b437d4101e0fbe44e88fc3ad5266fac12f400568198d',
            u'6623aada75e16d001f29955f33a68d489f158a08f515d50745f96d96452232e0',
            u'88a8dbf460a6ddb9357890cecc835f96889df7770cefbe999a3c2a0ed6042982',
            u'14d8f24500b70778fdf8c4ebcd98ce04fcb7c824262251b0aae0359dcbe34d8f',
            u'815750786992781fb144ac1176151467a1c24787732c62488b600e46adcf2471',
            u'2bd677ed05a5088dd03fa603849e3b3dde7b9cca2ddfe794625278fe8eac33ec',
            u'd3c429807b1f077fcefaef3501910b9b13e7c7331b56afc11be7e7735cc22e71',
            u'483d69143b27259c1f7f1bbdbbacdebb707103e705e5e0b9c07ffc2ec8986e9c',
            u'fd8ca31b142529fd7893e1fa443b0aa588c74afb86fa7a3dd167b026e8471ad1',
            u'f7c8249fbbeccc31fd3eb1122f458596f4a6177fe7498073ceac8eeba195feff',
            u'81052b0ca3e0257ae236bbb516b419d894f7938e1771e447b220d84ad66bf0ba',
            u'50bcfc57d4a5aaffb811530cc591aab4b30699c2eded645d95d2a0778928f122',
            u'23b7c0b708746ca70d37d85cb4154aa84d6c6f47644cbf1e5e69ba6ba174e793',
            u'18006412a0a225eff5c9d0561fb8002f3804864b86858bd3386af52427a84518',
            u'19cad084c6d94fbd1b43d582d3e04a757860d9dcebbde4b44b545a3b9e322bac',
            u'4a9a70c4c716b080bdbe1098641fbf2757c7d65f3d9b0c89926be9690473cd53',
            u'af5e2040b644947a5ede5164eeb953e2f6cacac1e081f6d350265af2a00ef720',
            u'01c347a1a162a72dedeba569349562df2a853e9a34e8399c8f81fab2d5c591aa',
            u'd4fe56d65f11bb777c87c063dd369018cf93ab58f32942a89781a72f8b515d83',
            u'a62f5e7db2f0fc6f7d258d5f6588cbf8480d8c63757eba7be173bd0ddb00c425',
            u'15f16534df8d59d613d5018ea62b235be2f6bc01bc239a10376601aa020cb7bc',
            u'e5adfaaad73d934fa5ebeb4bf0e5e40bff51a3b78edc05640830a469440d6615',
            u'1d7d878a0ae396dab92bde7e0df60562e9795bacc220944f79094b9ea7fb7680',
            u'8b1a7d50b4c388a5aefb4e0b26064f15aaf3f7129918050adb73e4e5af688334',
            u'427e92786ef3b589eda3458df3bd2c2f9799b8b3cbf210c99be9717092a64caa',
            u'85232adfecb2510f6a7951a3ce97776fbe48012b1d43ec9eae1cddd4222e0f97',
            u'bae6a239b58434321050c52d99acd109c9219081a943a7558023e9f5234fe1bc',
            u'1e8a3e6f8a4c5184bee08f144134b1eff209a81629ae8ffc26445aa60b6778e8',
            u'9f06ed34914823e48ce299b74c934044e618974a85396435c3afbd14d93a034a',
            u'c2abf971ed3b875e2214c3bb3b6cef6e3b9cfd7f71c80472654bf875291fec1a',
            u'f8efe2380bb7944f8fd2f95a177f6c3b4353c6a84a00a05076bf39a1abb80a79',
            u'31d20d04e0941bfac520487efcdde192addf6c3a768ade3992e91f23e181dd3a',
            u'e6f5c08d2899cfc63b8c72142174d7aac61f50893238b13e12ecbbd65356af73',
            u'deeb1340a234d64b1552e345923febb72fd14e85409af33d3e1aad7fc3a17fd5',
            u'e90b8f2244bde77c1859ad047220a36160a0097cab70cb2c78980b8b618a5f49',
            u'fa61d3985f21b3695664ce996905e7932b4c713e102632777f20a4cd664fdcc7',
            u'22e181b5a8333617daa57f70481cfb7639b7115e3bdc409b69a2a18dadde959a']
        deserial = [unhexlify(hsh)[::-1] for hsh in hashes]
        fake_coinbase = Transaction()
        fake_coinbase._hash = deserial[0]
        branch = merklebranch(deserial[1:], hashes=True, be=True)

        self.assertEquals(
            "35bc46dc56cd6bcb9844323c52eb894a29a3c60add8553a08281fb3eed62cdcf",
            hexlify(merkleroot(deserial, hashes=True, be=False)[0]).decode('ascii'))

        self.assertEquals(
            "35bc46dc56cd6bcb9844323c52eb894a29a3c60add8553a08281fb3eed62cdcf",
            hexlify(from_merklebranch(branch, fake_coinbase)))


class TestBlockTemplate(unittest.TestCase):
    def test_validate_scrypt(self):
        """ confirm scrypt validation of difficulty works properly """
        header_hex = ("01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3"
                      "b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509b"
                      "d073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4")
        header_bytes = header_hex.decode('hex')
        target = target_unpack(unhexlify("1d018ea7"))

        self.assertTrue(BlockTemplate.validate_scrypt(header_bytes, target))

    def test_block_header2(self):
        # pulled from litecoin blockchain and modded slightly with full block header
        block_data = {
            'bits': '1d018ea7',
            'hash': 'adf6e2e56df692822f5e064a8b6404a05d67cccd64bc90f57f65b46805e9a54b',
            'height': 29255,
            'merkleroot': '066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f',
            'nonce': hexlify(pack(str(">L"), 3562614017)),
            'previousblockhash': '279f6330ccbbb9103b9e3a5350765052081ddbae898f1ef6b8c64f3bcef715f6',
            'curtime': 1320884152,
            'raw_header': '01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4',
            'tx': [
                ('066b2a758399d5f19b5c6073d09b500d925982adc4b3edd352efe14667a8ca9f', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804b217bb4e022309ffffffff0100f2052a010000004341044870341873accab7600d65e204bb4ae47c43d20c562ebfbf70cbcb188da98dec8b5ccf0526c8e4d954c6b47b898cc30adf1ff77c2e518ddc9785b87ccb90b8cdac00000000')],
            'version': 1}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True)
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions, be=True)[0]), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.lehexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        pprint(coinbase.to_dict())
        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions)
        self.assertEquals(hexlify(tmplt.merkleroot_be(coinbase)),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'')
        self.assertEquals(block_data['raw_header'], hexlify(header))
        assert tmplt.validate_scrypt(header,
                                     target_unpack(unhexlify(block_data['bits'])))

    def test_block_header(self):
        return
        # pulled from dogecoin blockchain and modded slightly, height 50000
        block_data = {
            'bits': '1c00c7ec',
            'hash': 'e4cab588a33147a217c8bc2f923fcd1f642fde26c7c797a5c2c4808c4c617a7e',
            'height': 50000,
            'merkleroot': '5af19843e6220965f3c4b5f8d3995796edff0aad5ee4cc6ab849333881c001e1',
            'nonce': hexlify(pack(str(">L"), 3014526208)),
            'previousblockhash': '7f0502292609f5949260403176e8874ec7c5376397641d3f660648e7fdda0bab',
            'curtime': 1389349309,
            'tx': [
                ('d4eeb0cd44a4339d1a9fe8cea9482689165cff6ed1a3f4815bafcb443cdd271e', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff250350c300062f503253482f04bcc9cf5208f80032c0020000000b2f4e757432506f6f6c732f00000000010b54074f2f4b00001976a9141b3fdba0ff497a9d8e84d65e9b078e23e46e97f088ac00000000'),
                ('481fce0e2572dd782369dcc2457c267bb70918e825dfedd6e178ddf28d016cde', '0100000006ca0667d0021af9199f134a38ece3f813200f457282c2904d11b5c14a773ad514010000006b48304502200470b7b254b1d4b75f3318c6348ac97e2ba35f4be838aa10b50429107b4a8026022100864687886781c4a16de03b18fc5236bd379a6655f075b75da308b9bc3d7565b801210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff9f9316e06ba91ceb8d93a3f3b1286570ccc9f5720c944a556e37a11a0789d99a010000006b483045022100fc72dadfb07f7253b948bd94c3e9e534a4f45fdd70d6f25e865afc079f5f07ac022028be9ec4d68e700f5843a72e387f1a2bdf0cacb06f19ad8fbbc3db15ceaadd9401210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffffcc803949dfe10ac0d9b7adc4b560a52fdbfc3fbf5a2cd4c515bdc1ccee1919e6010000006a4730440220385fb14c3f6559557c6ff0a1beab9c0a3a1f3ee7b5c466874566f25063be13fb022001b84680899638bd99fcea1f8a007ccda4df954a594210a1e6b2644c681b56b601210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff340b8f285ceea5a123aaae8d33fd940442962894b8276a0f1d0959072c85b1e2010000006b4830450221008c592892fb530499f75065d4c741a97bb89e7aab7f156cf6471e134e41d19b3802202355e2f57c8ab27eb9445612e18f8ca0c51d0c8bad035082f784157db006419501210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff57835281cd613c9afc81e339d4d6b5ff20e25b381015b99ad863c3cec9c456d3010000006b48304502201ebdf69c6e146dc9f832d32439a1fef26011eecac1ffdc246ed37b726ca33f9a022100bb4e8f82c2c89c254700196f08e277af6964a04122a6395d42e61ffdbbb08ac601210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff5d22d9f2819f918f92bfb529c58201ed382a38d67a20c4277d104ecd92cb84c1010000006c493046022100834cfab229487cef0fe22dd07bbcf83bd3ce2696aee904b906c0cd8791e86a74022100a9dc16328ca8c648a0999d584fb1003fd4375aabe05d273143e976a735cf72f001210314309009775cf62a41fb7f0527e5bcda061e0b1f9dde2dc9cec7c7675453e901ffffffff010011133a4f0200001976a914db4d7ba9e58109182b04307cd587fc0c79f659e788ac00000000'),
                ('74c60a18fc9a265cf78973d36e20b781ae427d4d62e9818bc51de000ef6fb1e3', '0100000006ec24cf82341457fe1f4e5a8aa70cd0cd24577d55de00f0220687edb5c4b18f48000000006b483045022100ca65846ad4fddc08b6e36853f6d0175df6a967c0c76c2804f07e3efe4a07901002207b67d8a7ee76dcf45f9515589381cccd2db33cb602b85f3f1abc873bfd2bb0680121037c533b95e310e28de6ea11179dac58b5a44e6de5eb37aacdfcb33c7d3c241cdaffffffffdf50b75ca17711f4e7060684389eaba1f9b928e160021ceb5348d338ecc827fa010000006a47304402202eca6850b9c25e8974441dd386b58d9a615ab8527f46890d10861916ee25b87f02201d35044b1ec20d6d2ec2e292354acc5d65ae8be10bf57cbd17d51ce0ac07dd6c012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150fffffffff6157a915b05f2c5d823123fb4b230b045fdbff0f68578d44de49f78cf0ede5b010000006b48304502201b61e8486f039524fb5a2fd51fdc75c170502a4adc43fdfefb830abcf572b4d0022100b5f134301962e661e8251f79182344d879dbd990c0513b6ee96ad45ffb5b9475012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffd48aed18cad37e0d0f5bbcdd1b7f0a56899bdae664164dab0e243be02761a9ba010000006b483045022100c0c06d4fb2ec9f473f3b5fe9e96ab1379f9431cc639256a780d395b8c816a801022049c38e24224e02c7d103dbb4ffe650f86a85efbbd06e09f14bb68289813a88ce012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffbb1f79fb8ef08188bbe5720afc51e8d4b17b227ac0575e06b113e9aa2cf73c9a010000006b483045022100de8dfc418ca7e9cbc3b8cee601e06ded8519490c3e3a69ad445e4bdbae6646a50220675e874008150d6c407211588819d42640e873cd5124a6acedfc66c7f5aae088012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffffdc2dff24673739435ef472cedc633557f21c6909822a40136c4b75c08797f6f7010000006a473044022045c537da10375757cb53ec70c06c6f00011c0759bdf8e6df2a012ce33153c7e102206e1e35d6f57c7de5ad37272efdecaf7313ada0e8f66f9532dd0747b09cb8003e012102720d51af78046f9454039c958c592358e637e46b43184f837d6a5572056a5150ffffffff0231cc5893000000001976a914262fee33cefdf111c3515c0502ba69073609904888ac0038c566e40200001976a914bd007a5819157bc912364e54fe7e0551df06d54888ac00000000'),
                ('12127842a829a588be0ac25a3ab5505925e79440d6911d22dd1059c79b9966e7', '0100000002ac367cb4c2ebd51066b0a87bac57a0f4876a6be781b1d2935bb49d1320c735f7000000006b48304502207a58e61dbe5ab39e7f6b3a91bf62a33102dfc6e7d2270d0f2cd31d0fd2b58a4a022100f27ffec655cf27ce9d4facbc9ce1b079f0c7b3fe80db69111695825e23628209012102c9619b298f6272cd0710ff5997f38dfd39096e3c95b92f857da6f4843e4afbc7ffffffff6c7fc27f6debb16714276edf12868ab5deab5a0cd64c5152928a2f3798e1ee01000000006c493046022100895790720f307d12a41a6df11c83fe2c991a857e63048e74dde91fb672a368ea022100bf9dac5625b454ee38dba9fc7e8e911bf5dc8cf504709413a9b12adb9b77bc26012103dedeabe4b6166d97479db844ca2defbbb8c5394b7576aafd6be67175062dc4beffffffff01008fd3ac8b0000001976a91464e5cfa48bf5f22ce5a5e739667ef61afb0b192d88ac00000000'),
                ('48d5713b929e28f1810cc7effdbfb0cb11bc88068bfbb1c9f076536b794715af', '010000000501049ee2eba48bf43470d5a6c1328fc29e3f434cae2f92d6b55bc6b694083d4f010000006a4730440220656c1c8c96ac2e72451e1ac69e496ee3768cd35741a4605579a770bde17ebe8e02207b0093e79f4f9e99795575699fd38496b2b12ce1b994054505c52dc9092a2bba01210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff17765b1d45fc0f0b0d9e060291bfaf19b9a219f3a74fb1fb6e20fda3278f252f010000006b4830450220264601cb87ca3579f4653248dfb539bd13bea41c63d378ab7ec86f5476ea99ab022100e5921d7d5b7c5421cf17a46729d1e08b26cfe3d64120d46a4c0faa623f91791301210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff94a09224a810a12eb793cb87802f58e31e5fc1f38831be221a4d2f9910893dcb010000006c4930460221008160791119449e306c9db0b3f22dde248bbc73babd732052b26a58b29c86287b022100ccdd9cb9eb9d8791c45b691d09f5aba2bfd69f279edd9c8177942748a5075ed901210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff9c9431729394c53656a625755dd2ff124a0d615932a2ea6befafd36812301ae0010000006a47304402202930eda28e865b8d190a305611473760df2b151175bc834155bc58435e82955102206eb77aceae4149715002ea4fee6eb2ffd807c1dc3fd37ea1d7eb28e88733883401210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffffae32166a760609d5fae1361f568977fb23e108a480a328298f075603a2bd124d010000006b48304502210094586a38aaa22ac5f1cb85871236057ae2fb8412fe5128768f2435eeadff0d8402202bd0000b2ddad2f1da83cfec60513aea0724f477bb55d5150e0de31955710c0d01210345c22d21ffaed0e492bd96c65f512757b7062964c8a69cbcbdc08d4139cdf561ffffffff0100bccfcd5a0000001976a91442f319a15fd608b67ddddcc2e3badf1b90554fe088ac00000000'),
                ('212499f6527467b49cdf946524b42266ca8751616a41b7181d3a8931da7b240e', '01000000018fa554391f4e45ae96b9c6e9bd35f1cf38737ee9ad67ba401329df7497625513000000006b483045022019331f164d059057e5dc12bab158678ba65faf1b9542811434ce13e1179550b4022100e2375b7f350b18c1bde49c8ddd7d245282b931e1a8204018bb01b8abff94f4790121038f63d5c111706674f50f3d28729fe9848e9a3aee0b965c674d14e2155c5ee35bffffffff0200a3af46bb0000001976a9149cc45c2d78927f22ab4008a907becf6ab642258288aca019f807000000001976a9144d4952746b2777f3d07a89ad0ffd02e2e1d9aed288ac00000000'),
                ('47bce257235ab0f6c8526a12fc23e3bec10bbd1d87a3a261f624ff5c0d2730f2', '0100000001a16eaa30e2d56f3a3a94bf4b640c2ffaa3ccd09ce3926567b2e63e3f4d55df26000000006b48304502203579c6afe9b7365252c0424aa5e3b9d00c850f2beee0c0b2f66ac7652c4eb002022100ca44a4a0e7d2ff81de117efd144a89c70acc87eaf2e3454fed175f0ef9b6f562012103f5f17ee5b476803cf332d56c293ce59aa77a5046a284c9f7a523fefd911e9980ffffffff0260119d0a010000001976a9149e027ca13765f6558fcbab6acec2fc561fc5dd3288ac9ec1764b010000001976a914957acdecb251260da54dc8510497cb761db0698c88ac00000000'),
                ('6b74e1534ee50fc7158593831e322717fa536d65cbeb03fe53b30b31853fa033', '010000000153323c2dbba06bc58227354b013d31ba01ba814fa5681fb211c039979cac1643000000006b483045022054f7930a06af7da2a3e35c3fbb9bb0fbf5897c9296286de46d96763ea8c1d8fc0221009b8d53d5964a57fc8469ece1b0ef6f43e2cdbe1d4d72308d04491cb4705f95ce012103bbd11e6843ebcbcd2024265332738d8e1ebc7d0bb4b3a2e5b7a8bd6ece14bcb7ffffffff029feec0e4000000001976a91481d7f7a63b4a4e236b3b5d43067212e52bcd25ae88acf73d7520000000001976a91447cd32e2669d30d86d1c6708b890b9d7c7b632f188ac00000000')],
            'version': 1}
        # make a list of objects
        # confirm that the objects hash correctly
        coinbase = None
        transactions = [Transaction(unhexlify(data.encode('ascii')), disassemble=True)
                        for _, data in block_data['tx']]
        self.assertEquals(hexlify(merkleroot(transactions)[0]), block_data['merkleroot'])
        for obj, hsh in zip(transactions, block_data['tx']):
            hsh = hsh[0]
            obj.disassemble()
            self.assertEquals(obj.lehexhash, hsh)
            if obj.is_coinbase:
                idx = transactions.index(obj)
                coinbase = transactions.pop(idx)
                print("Found coinbase idx {} Amount is {}"
                      .format(idx, coinbase.outputs[0].amount))

        tmplt = BlockTemplate.from_gbt(block_data, coinbase,
                                       transactions=transactions)
        self.assertEquals(hexlify(tmplt.merkleroot(coinbase)),
                          block_data['merkleroot'])
        header = tmplt.block_header(block_data['nonce'], b'', b'')
        assert tmplt.validate_scrypt(header, target_unpack(unhexlify(block_data['bits'])))

    def test_stratum_confirm(self):
        """ Test some raw data from cgminer submitting a share, confirm
        hashes come out the same as cgminer.
        Raw stratum params:
        """
        gbt = {u'bits': u'1e00e92b',
               u'coinbaseaux': {u'flags': u'062f503253482f'},
               u'coinbasevalue': 5000000000,
               u'curtime': 1392509565,
               u'height': 203588,
               u'mintime': 1392508633,
               u'mutable': [u'time', u'transactions', u'prevblock'],
               u'noncerange': u'00000000ffffffff',
               u'previousblockhash': u'b0f5ecb62774f2f07fdc0f72fa0585ae3e8ca78ad8692209a355d12bc690fb73',
               u'sigoplimit': 20000,
               u'sizelimit': 1000000,
               u'target': u'000000e92b000000000000000000000000000000000000000000000000000000',
               u'transactions': [],
               u'version': 2}

        extra1 = '0000000000000000'
        submit = {'extra2': '00000000', 'nonce': 'd5160000',
                  'result': '000050ccfe8a3efe93b2ee33d2aecf4a60c809995c7dd19368a7d00c86880f30'}

        # build a block template object from the raw data
        coinbase = Transaction()
        coinbase.version = 2
        coinbase.inputs.append(Input.coinbase(gbt['height'], b'\0' * 12))
        coinbase.outputs.append(Output.to_address(gbt['coinbasevalue'], 'D7QJyeBNuwEqxsyVCLJi3pHs64uPdMDuBa'))

        transactions = []
        for trans in gbt['transactions']:
            new_trans = Transaction(unhexlify(trans['data']), fees=trans['fee'])
            assert trans['hash'] == new_trans.lehexhash
            transactions.append(new_trans)
        bt = BlockTemplate.from_gbt(gbt, coinbase, 12, transactions)
        send_params = bt.stratum_params()
        print("job_id: {0}\nprevhash: {1}\ncoinbase1: {2}\ncoinbase2: {3}"
              "\nmerkle_branch: {4}\nversion: {5}\nnbits: {6}\nntime: {7}"
              .format(*send_params))

        header = bt.block_header(submit['nonce'], extra1, submit['extra2'])
        hash_bin = scrypt(header)
        target = target_from_diff(1, 0x0000FFFF00000000000000000000000000000000000000000000000000000000)

        hash_int = uint256_from_str(hash_bin)
        hash_hex = "%064x" % hash_int
        self.assertEquals(hash_hex, submit['result'])
        assert hash_int < target


class TestInput(unittest.TestCase):
    def test_coinbase_numeric(self):
        inp = Input.coinbase(120000)
        assert int.from_bytes(inp.script_sig[1:], byteorder='little') == 120000
        assert int.from_bytes(inp.script_sig[:1], byteorder='little') == 3


class TestUtil(unittest.TestCase):
    def test_target_unpack(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_unpack(b"\x1d\x00\xff\xff"),
            0x00000000FFFF0000000000000000000000000000000000000000000000000000)

    def test_target_from_diff(self):
        # assert a difficulty of zero returns the correct integer
        self.assertEquals(
            target_from_diff(1),
            0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    def testb58(self):
        assert get_bcaddress_version('15VjRaDX9zpbA8LVnbrCAFzrVzN7ixHNsC') is 0
        _ohai = 'o hai'.encode('ascii')
        _tmp = b58encode(_ohai)
        assert _tmp == 'DYB3oMS'
        assert b58decode(_tmp, 5) == _ohai


class TransactionTests(unittest.TestCase):
    def test_coinbase(self):
        coinbase = Transaction()
        coinbase.version = 2
        coinbase.inputs.append(Input.coinbase(12000, b'\0' * 6))
        coinbase.outputs.append(
            Output.to_address(50000, 'D7QJyeBNuwEqxsyVCLJi3pHs64uPdMDuBa'))
        one, two = coinbase.assemble(split=True)
        one = one[:-6]

        test = Transaction(one + unhexlify('0abcdef01012') + two)
        test.disassemble()
