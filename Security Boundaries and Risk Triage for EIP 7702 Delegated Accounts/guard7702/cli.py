"""Offline authorization demos, normalized observation scoring, and benchmarks."""
import argparse
import json
import sys
from pathlib import Path
from .detector import WEIGHTS, inspect


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def demo():
    from eth_keys import keys
    from .protocol import World, sign
    key = (1).to_bytes(32, 'big')  # Public test key; never fund.
    authority = keys.PrivateKey(key).public_key.to_address()
    sponsor, target = '0x'+'22'*20, '0x'+'33'*20
    auth = sign(key, 0, target, 0)
    outcomes = {}
    for chain in (1, 31337):
        world = World(chain)
        first = world.process(sponsor, [auth])
        replay = world.process(sponsor, [auth])
        outcomes[str(chain)] = dict(first_submission=first['outcomes'][0]['reason'],
                                    same_chain_replay=replay['outcomes'][0]['reason'],
                                    authority_nonce=world.accounts[authority].nonce,
                                    delegation_code='0x'+world.accounts[authority].code.hex())
    return dict(mode='offline model', authority=authority, chains=outcomes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo', help='signed authorization and replay demo')
    scan = commands.add_parser('inspect', help='score UTF-8 JSONL observations')
    scan.add_argument('input', type=Path)
    scan.add_argument('--threshold', type=positive_int, default=4)
    bench = commands.add_parser('benchmark', help='deterministic synthetic checks')
    bench.add_argument('--output', type=Path, default=Path('results'))
    bench.add_argument('--seeds', type=positive_int, default=20)
    bench.add_argument('--events', type=positive_int, default=2000)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            print(json.dumps(demo(), indent=2))
        elif args.command == 'benchmark':
            from .benchmark import run
            print(json.dumps(run(args.output, args.seeds, args.events), indent=2))
        else:
            with args.input.open(encoding='utf-8') as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                        if not isinstance(event, dict):
                            raise ValueError('expected a JSON object')
                        for feature in WEIGHTS:
                            if type(event.get(feature)) is not bool:
                                raise ValueError(f'{feature} must be present and boolean')
                    except ValueError as exc:
                        raise ValueError(f'line {line_number}: {exc}') from exc
                    print(json.dumps(inspect(event, args.threshold)))
    except (OSError, ValueError) as exc:
        print(f'guard7702: {exc}', file=sys.stderr)
        return 2
    return 0
