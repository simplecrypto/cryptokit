from cryptokit.block import BlockTemplate
from cryptokit.transaction import Transaction, Input, Output

def test_block_template():
    gbt = {u'coinbaseaux': {u'flags': u''}, u'vbavailable': {}, u'previousblockhash': u'00000061786317587bcfe97516cd00a541962334779d60efdb7c4efeb670ac77', u'target': u'7fffff0000000000000000000000000000000000000000000000000000000000', u'noncerange': u'00000000ffffffff', u'transactions': [], u'rules': [], u'vbrequired': 0, u'curtime': 1500584586, u'capabilities': [u'proposal'], u'height': 16, 'update_time': 1500584586.899153, u'mintime': 1500584329, u'version': 536870912, u'bits': u'207fffff', u'coinbasevalue': 5000000000, u'sigoplimit': 20000, u'sizelimit': 1000000, u'mutable': [u'time', u'transactions', u'prevblock'], u'longpollid': u'00000061786317587bcfe97516cd00a541962334779d60efdb7c4efeb670ac7718'}
    extranonce_length = 4
    coinbase = Transaction()
    coinbase.version = 2

    coinbase.inputs.append(
        Input.coinbase(gbt['height'], [], extra_script_sig=b'\0' * extranonce_length))

    coinbase_value = 10000000
    coinbase.outputs.append(Output.to_address(coinbase_value, "1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX"))

    bt_obj = BlockTemplate.from_gbt(gbt, coinbase, extranonce_length, [])
