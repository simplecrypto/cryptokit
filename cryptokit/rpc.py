"""
  Copyright 2014 Isaac Cook

  CoinserverRPC has the following improvements over python-bitcoinrpc
  AuthServiceProxy class:

  - Uses urllib3 to support automatic threadsafe connection pooling. Original
    version didn't make garuntees about thread pre-emption problems with
    sharing a single proxy object among multiple threads.
  - Attempts to offer more python exceptions
  - Makes no attempts to be backwards compatible

  Previous copyright, from python-bitcoinrpc/bitcoinrpc/authproxy.py:
  =========================================================
  Copyright 2011 Jeff Garzik

  AuthServiceProxy has the following improvements over python-jsonrpc's
  ServiceProxy class:

  - HTTP connections persist for the life of the AuthServiceProxy object
    (if server supports HTTP/1.1)
  - sends protocol 'version', per JSON-RPC 1.1
  - sends proper, incrementing 'id'
  - sends Basic HTTP authentication headers
  - parses all JSON numbers that look like floats as Decimal
  - uses standard Python json lib

  Previous copyright, from python-jsonrpc/jsonrpc/proxy.py:
  =========================================================
  Copyright (c) 2007 Jan-Klaas Kollhof

  This file is part of jsonrpc.

  jsonrpc is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  This software is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this software; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
"""

import urllib3
import base64
import json
import decimal
# For python3 support (module was renamed)
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse


class CoinRPCException(Exception):
    def __init__(self, rpc_error):
        self.error = rpc_error
        if isinstance(rpc_error, dict):
            # Easy access to the error attributes from the coinserver
            self.code = int(rpc_error.get('code'))
            self.rpc_error = rpc_error.get('message')

        super(CoinRPCException, self).__init__(str(self.rpc_error))


# General application defined errors
RPC_MISC_ERROR                  = -1, "std::exception thrown in command handling"
RPC_FORBIDDEN_BY_SAFE_MODE      = -2, "Server is in safe mode, and command is not allowed in safe mode"
RPC_TYPE_ERROR                  = -3, "Unexpected type was passed as parameter"
RPC_INVALID_ADDRESS_OR_KEY      = -5, "Invalid address or key"
RPC_OUT_OF_MEMORY               = -7, "Ran out of memory during operation"
RPC_INVALID_PARAMETER           = -8, "Invalid, missing or duplicate parameter"
RPC_DATABASE_ERROR              = -20, "Database error"
RPC_DESERIALIZATION_ERROR       = -22, "Error parsing or validating structure in raw format"

# Connection/Response errors
RPC_UNKN_CONN_ERROR             = -23, "Urllib http exception thrown in connection handling"
RPC_MAX_RETRIES_EXCEEDED_ERROR  = -24, "Max connection attempts exceeded"
RPC_READ_TIMEOUT_ERROR          = -25, "Maximum time spent waiting for a response was exceeded"
RPC_NOT_JSON_ERROR              = -26, "Response was not valid JSON"

# P2P client errors
RPC_CLIENT_NOT_CONNECTED        = -9, "Bitcoin is not connected"
RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10, "Still downloading initial blocks"

# Wallet errors
RPC_WALLET_ERROR                = -4, "Unspecified problem with wallet (key not found etc.)"
RPC_WALLET_INSUFFICIENT_FUNDS   = -6, "Not enough funds in wallet or account"
RPC_WALLET_INVALID_ACCOUNT_NAME = -11, "Invalid account name"
RPC_WALLET_KEYPOOL_RAN_OUT      = -12, "Keypool ran out, call keypoolrefill first"
RPC_WALLET_UNLOCK_NEEDED        = -13, "Enter the wallet passphrase with walletpassphrase first"
RPC_WALLET_PASSPHRASE_INCORRECT = -14, "The wallet passphrase entered was incorrect"
RPC_WALLET_WRONG_ENC_STATE      = -15, "Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)"
RPC_WALLET_ENCRYPTION_FAILED    = -16, "Failed to encrypt the wallet"
RPC_WALLET_ALREADY_UNLOCKED     = -17, "Wallet is already unlocked"


class CoinserverRPC(object):
    USER_AGENT = "CoinserserverRPC/0.2"
    HTTP_TIMEOUT = 30

    def __init__(self, service_url=None, service_name=None,
                 pool_kwargs=None, parent=None, headers=None):
        if parent:
            self._conn = parent._conn
            self._url = parent._url
            self._id_count = parent._id_count
            self._service_name = service_name
            return

        url, auth = self.parse_url_string(service_url)
        pool_kwargs = pool_kwargs or {}
        headers = headers or {}

        self.pool_kwargs = dict(maxsize=5, block=True)
        self.pool_kwargs.update(pool_kwargs)

        self.headers = {'Host': url.hostname,
                        'User-Agent': self.USER_AGENT,
                        'Authorization': auth,
                        'Content-type': 'application/json'}
        self.headers.update(headers)

        self._url = url
        self._service_name = service_name
        self._id_count = 0

        if url.scheme == 'https':
            cls = urllib3.HTTPSConnectionPool
        else:
            cls = urllib3.HTTPConnectionPool

        self._conn = cls(url.hostname,
                         url.port,
                         timeout=self.HTTP_TIMEOUT,
                         headers=self.headers,
                         **self.pool_kwargs)

    def parse_url_string(self, service_url):
        url = urlparse.urlparse(service_url)
        if url.port is None:
            if url.scheme == 'https':
                url.port = 443
            else:
                url.port = 80
        (user, passwd) = (url.username, url.password)
        try:
            user = user.encode('utf8')
        except AttributeError:
            pass
        try:
            passwd = passwd.encode('utf8')
        except AttributeError:
            pass
        authpair = user + b':' + passwd
        return url, b'Basic ' + base64.b64encode(authpair)

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError
        if self._service_name is not None:
            name = "{}.{}".format(self._service_name, name)
        return CoinserverRPC(service_name=name, parent=self)

    def __call__(self, *args):
        self._id_count += 1

        postdata = json.dumps({'version': '1.1',
                               'method': self._service_name,
                               'params': args,
                               'id': self._id_count})
        try:
            response = self._conn.urlopen('POST', self._url.path, postdata)

        except urllib3.exceptions.MaxRetryError:
            raise CoinRPCException({
                'code': -24, 'message': 'RPC connection failed, maximum retries'
                                        ' exceeded.'})
        except urllib3.exceptions.ReadTimeoutError:
            raise CoinRPCException({
                'code': -25, 'message': 'RPC connection failed, maximum time '
                                        'spent waiting for a response was '
                                        'exceeded'})
        except urllib3.exceptions.HTTPError as e:
            raise CoinRPCException({
                'code': -23, 'message': 'Unable to connect to server: '
                                        '{}'.format(e)})
        return self._get_response(response)

    def _batch(self, rpc_call_list):
        postdata = json.dumps(list(rpc_call_list))
        try:
            response = self._conn.urlopen('POST', self._url.path, postdata)
        except urllib3.exceptions.HTTPError as e:
            raise CoinRPCException("Unable to connect to server: {}"
                                   .format(e))
        return self._get_response(response)

    def _get_response(self, response):
        if response is None:
            raise CoinRPCException({
                'code': -342, 'message': 'missing HTTP response from server'})

        try:
            response = json.loads(response.data.decode('utf8'),
                                  parse_float=decimal.Decimal)
        except ValueError:
            raise CoinRPCException({
                'code': -26, 'message': 'Return type not JSON'})

        if 'error' not in response:
            raise CoinRPCException({
                'code': -343, 'message': 'missing JSON-RPC error code'})

        if response['error'] is not None:
            raise CoinRPCException(response['error'])
        elif 'result' not in response:
            raise CoinRPCException({
                'code': -343, 'message': 'missing JSON-RPC result'})

        return response['result']
