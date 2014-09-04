import argparse
import logging
import sys

from cryptokit.wallet import Wallet


logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(prog='simplecoin RPC')
    parser.add_argument('-l', '--log-level',
                        default="INFO", choices=['DEBUG', 'INFO', 'WARN', 'ERROR'])
    subparsers = parser.add_subparsers(title='main subcommands', dest='action')

    dump = subparsers.add_parser('dump_wallet', help='dumps the contents of a wallet file')
    dump.add_argument('-w', '--wallet', help='Path to the wallet file')
    dump.add_argument('-v', '--version', help='Address version', type=int)

    check = subparsers.add_parser('check_balance', help='pings a block explorer to get total wallet value')
    check.add_argument('-w', '--wallet', help='Path to the wallet file')
    check.add_argument('-v', '--version', help='Address version', type=int)
    check.add_argument('-b', '--block-explorer', help='An abe block explorer to connect to')

    args = parser.parse_args()

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s'))
    root = logging.getLogger()
    root.setLevel(getattr(logging, args.log_level))
    root.addHandler(handler)

    if args.action == "dump_wallet":
        t = Wallet.from_wallet_path(args.wallet, args.version)
        import pprint
        pprint.pprint(t.read())

    if args.action == "check_balance":
        import requests
        t = Wallet.from_wallet_path(args.wallet, args.version)
        data = t.read()
        total = 0
        failures = 0
        for key in data['keys']:
            try:
                amount = requests.get(args.block_explorer + "/addressbalance/{}".format(key['addr'])).json()
            except Exception:
                logger.error("Failed to fetch balance for address {}".format(key['addr']))
                failures += 1
            else:
                total += amount

        print "Total {}".format(total)
        print "Failures {}".format(failures)


if __name__ == "__main__":
    main()
