import datetime
import logging
import pprint
import decorator

from cryptokit.rpc import CoinRPCException, CoinserverRPC


@decorator.decorator
def rpc_conn(func, *args, **kwargs):
    """
    Catches all uncaught exceptions and coerces them to a CoinRPCException
    """
    try:
        res = func(*args, **kwargs)
    except Exception as e:
        raise CoinRPCException(
            {'code': -1, 'message': 'Unhandled error in \'{}\': {}'.
            format(e.__class__.__name__, e)})
    else:
        return res


class CoinTransaction(object):
    """
    Treating transactions pulled from the coin rpc as objects is convenient
    """
    def __init__(self, txid, currency, quantity, confirmations, fee, time,
                 blockhash):
        self.tx_id = txid
        self.currency = currency
        self.quantity = quantity
        self.confirmations = confirmations
        self.fee = fee
        self.time = time
        self.blockhash = blockhash

    @classmethod
    def create(cls, tx_info, currency):

        tx = cls(txid=tx_info['txid'],
                 currency=currency,
                 quantity=tx_info['amount'],
                 confirmations=tx_info['confirmations'],
                 fee=tx_info.get('fee'),
                 time=datetime.datetime.fromtimestamp(tx_info['time']),
                 blockhash=tx_info.get('blockhash'))

        # Fix things for Syscoin edge case
        if currency == 'SYS':
            tx.quantity = tx_info['fee'] + tx_info['amount']

        return tx


class CoinRPC(object):
    """
    Treating the RPC as a python object is pretty convenient. All possible
    exceptions thrown by RPC code are raised as CoinRPCException, making
    error handling pretty easy
    """

    def __getattr__(self, attr):
        return self.config[attr]

    def _set_config(self, **kwargs):
        # A fast way to set defaults for the kwargs then set them as attributes
        self.config = dict(maxsize=10,
                           tx_fee=0,
                           min_confirms=6,
                           enabled=True,
                           account="",
                           logger_name="coin_rpc",
                           log_level="INFO")
        self.config.update(kwargs)

        required_conf = ['coinserv', 'currency_code']
        error = False
        for req in required_conf:
            if req not in self.config:
                print("{} is a required configuration variable".format(req))
                error = True

        coinserv_required_conf = ['username', 'password', 'address', 'port']
        for req in coinserv_required_conf:
            if req not in self.coinserv:
                print("{} is a required coinserv configuration variable".format(req))
                error = True

        if error:
            raise CoinRPCException(
                {'code': -1, 'message': 'Errors occurred while configuring '
                                        'CoinRPC obj'})

    def __init__(self, config, logger=None):
        if not config:
            raise CoinRPCException(
                {'code': -1, 'message': 'Invalid configuration file'})

        self._set_config(**config)

        if logger:
            self.logger = logger
        else:
            logging.Formatter.converter = datetime.time.gmtime
            self.logger = logging.getLogger(self.config['logger_name'])
            self.logger.setLevel(getattr(logging, self.config['log_level']))

        self.conn = CoinserverRPC("http://{0}:{1}@{2}:{3}/"
            .format(self.coinserv['username'], self.coinserv['password'],
                    self.coinserv['address'], self.coinserv['port'],
                    pool_kwargs=dict(maxsize=self.maxsize)))

    @rpc_conn
    def poke_rpc(self):
        return self.conn.getinfo()

    @rpc_conn
    def set_tx_fee(self, amount):
        amount = float(amount)

        try:
            self.conn.settxfee(amount)
        except CoinRPCException:
            self.logger.warn("{} coinserver reported failure attempting to "
                             "set tx fee to {}".
                             format(self.currency_code, amount), exc_info=True)
            raise
        else:
            self.logger.info("{} coinserver tx fee set to {}".
                             format(self.currency_code, amount))

    @rpc_conn
    def get_transaction(self, coin_tx):
        """
        Runs gettransaction rpc call

        gettransaction sample output:

        {u'amount': Decimal('0.37810015'),
         u'blockhash': u'321e3dc1ad953ce585bbc2863effd29976f7f432e82e0af5a0e9a84ea096f373',
         u'blockindex': 2,
         u'blocktime': 1406482864,
         u'confirmations': 22,
         u'details': [{u'account': u'personal_mining_address',
                       u'address': u'VvAQomockqLj5uto6UKq7EXGAAxpkcWAio',
                       u'amount': Decimal('0.37810015'),
                       u'category': u'receive'}],
         u'time': 1406482863,
         u'timereceived': 1406482863,
         u'txid': u'd405e871740cc058e2121144362f18012f14e6d3ef702afa343c4c10469642c0'}
        """

        try:
            tx_info = self.conn.gettransaction(coin_tx)
        except CoinRPCException as e:
            if e.code == -5:
                self.logger.warn('Transaction {} not found in the {} '
                                 'wallet'.format(coin_tx, self.currency_code))
                raise
            else:
                raise

        self.logger.info("Found local info on {} TX {}"
                         .format(self.currency_code, coin_tx))
        self.logger.debug(pprint.pformat(tx_info))
        try:
            tx = CoinTransaction.create(tx_info, self.currency_code)
        except (KeyError, AssertionError):
            self.logger.warn('Got unexpected Coin RPC gettransaction '
                             'response \n{}'.format(pprint.pformat(tx_info)),
                             exc_info=True)
            raise CoinRPCException
        else:
            return tx

    @rpc_conn
    def list_transactions(self, account="''", count=10):
        """
        Runs the 'listtransactions' rpc call on the given currency's rpc server
        and returns transactions

        listtransactions sample output:

        [
            {
                "account" : "scm",
                "address" : "LKyGLZ4tLYjWEDGFzT94KvCdUFYvm7KyXj",
                "category" : "send",
                "amount" : -7.97790612,
                "fee" : 0.00000000,
                "confirmations" : 2819,
                "blockhash" : "2da8acefd9e9b5c0c2b0ccb655e1423c950a8c7877847c614f48a5e55235026f",
                "blockindex" : 1,
                "blocktime" : 1410849255,
                "txid" : "0e9b03a9d212263b1c28a9945463a8d3d451926885b2f2c2106f49c8fd6bbc95",
                "time" : 1410849251,
                "timereceived" : 1410849251
            }
        ]
        """
        result = self.conn.listtransactions(account, count)

        self.logger.debug("Received {} {} transactions"
                          .format(len(result), self.currency_code))

        transactions = []
        try:
            for tx_info in result:
                tx = CoinTransaction.create(tx_info, self.currency_code)
                transactions.append(tx)
        except KeyError as e:
            self.logger.warn("Key error grabbing {} transactions. Got: {}"
                             .format(self.currency_code, e))
            raise CoinRPCException
        else:
            return transactions

    @rpc_conn
    def unlock_wallet(self, seconds=10):
        if self.coinserv['wallet_pass']:
            try:
                wallet = self.conn.walletpassphrase(self.coinserv['wallet_pass'], seconds)
            except CoinRPCException as e:
                # Some wallets get grumpy about unlock attempts when they're
                # not encrypted
                if e.code == -15:
                    self.logger.warn("Unlocking {} wallet unnecessary, its "
                                     "not encrypted. You should probably "
                                     "encrypt it...".format(self.currency_code))
            else:
                self.logger.info("Unlocking {} wallet. Success: {}".
                                 format(self.currency_code, wallet))

    @rpc_conn
    def send_many(self, account, recip):
        """
        Runs the 'sendmany' rpc call on the given currency's rpc server
        """
        # Coercy account to a STR
        account = str(account)

        # Coerce all amounts to float
        for k, amount in recip.iteritems():
            recip[k] = float(amount)

        self.unlock_wallet()
        self.set_tx_fee(self.tx_fee)

        try:
            coin_tx = self.conn.sendmany(account, recip)
        except CoinRPCException as e:
            self.logger.error("Unable to send funds! CoinRPC returned an error "
                              "{}".format(e), exc_info=True)
            raise CoinRPCException
        else:
            self.logger.info("Successfully ran sendmany for {} to {}".
                             format(self.currency_code, recip))

            # Lookup the transaction we just created to grab fees
            tx = self.get_transaction(coin_tx)

            return coin_tx, tx

    @rpc_conn
    def get_balance(self, account=None):
        """
        Runs the 'getbalance' rpc call on the given currency's rpc server
        """
        if not account and not self.account:
            balance = self.conn.getbalance()
        else:
            balance = self.conn.getbalance(account or self.account)

        self.logger.info("Found {} {} balance in local wallet".
                         format(balance, self.currency_code))
        return balance

    @rpc_conn
    def get_block(self, block_hash):
        """
        Runs the 'getblock' rpc call on the given currency's rpc server
        """
        block_info = self.conn.getblock()
        self.logger.debug("For block {} received info:".format(block_hash,
                                                               block_info))

        try:
            assert 'height' in block_info
            assert 'confirmations' in block_info
            assert 'hash' in block_info
        except AssertionError:
            self.logger.warn('Got unexpected {} RPC getblock response. Got: {}'
                             .format(self.currency_code, pprint.pformat(block_info)),
                             exc_info=True)

        return block_info

    @rpc_conn
    def get_transactions_since(self, blockhash, confirms=1):
        """
        Runs the 'listsinceblock' rpc call on the given currency's rpc server
        and returns transactions

        listsinceblock sample output:

        { "lastblock" : "0000000004ba22e9f8cea2e843b34f7eeaa2c3b7004ddcf19bfd8af0215fc0cc",
          "transactions" : [ { "account" : "",
                "address" : "mzE6DJMHPghYpVg4GCurMbxSSXBfW1KCFH",
                "amount" : 1.0,
                "category" : "receive",
                "confirmations" : 0,
                "time" : 1399200157,
                "timereceived" : 1399200157,
                "txid" : "917248d57293a7fd3a88aa3a26026d2e4d6a1d4eef898519b20419f2339c265c",
                "walletconflicts" : [  ]
              } ]
        }
        """
        result = self.conn.listsinceblock(blockhash, confirms)

        self.logger.info("For {} block {} received : {}"
                         .format(self.currency_code, blockhash, result))

        transactions = []
        try:
            for tx_info in result['transactions']:
                tx = CoinTransaction.create(tx_info, self.currency_code)
                transactions.append(tx)
            lastblock = result['lastblock']
        except KeyError as e:
            self.logger.warn("Key error grabbing {} transactions since {}"
                             " Got: {}".format(blockhash, self.currency_code, e))
            raise CoinRPCException
        else:
            return transactions, lastblock

    @rpc_conn
    def get_received(self, address, confirms=1):
        """
        Runs the 'receivedbyaddress' rpc call on the given currency's rpc
        server and returns tx ids
        """
        results = self.conn.receivedbyaddress(address, confirms)
        self.logger.info("For {} block {} received : {}"
                         .format(self.currency_code, results))
        for result in results:
            try:
                transactions = result['txids']
            except KeyError as e:
                self.logger.warn("Key error with {} txids for {}. Got: {}"
                                 .format(self.currency_code, address, e))
                raise CoinRPCException
            else:
                return transactions

    @rpc_conn
    def get_block_count(self):
        """
        Runs the 'getblockcount' rpc call on the given currency's rpc server
        and returns the count
        """
        count = self.conn.getblockcount()
        self.logger.info("Got {} height for: {}"
                         .format(count, self.currency_code))
        return count

    @rpc_conn
    def get_block_hash(self, index):
        """
        Runs the 'getblockhash' rpc call on the given currency's rpc server
        and returns the height
        """
        hash = self.conn.getblockhash(index)
        self.logger.info("For {} height {} received : {}"
                         .format(self.currency_code, index, hash))
        return hash