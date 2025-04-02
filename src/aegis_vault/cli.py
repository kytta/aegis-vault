from __future__ import annotations

from collections.abc import Sequence

from aegis_vault.converter import make_converter
from aegis_vault.vault import VaultFile

converter = make_converter()


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    from getpass import getpass
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "infile",
        nargs="?",
        default=sys.stdin,
        type=argparse.FileType("rb"),
    )
    parser.add_argument(
        "outfile",
        nargs="?",
        default=sys.stdout,
        type=argparse.FileType("rb"),
    )
    args = parser.parse_args(argv)

    with args.infile as fd:
        vault = converter.loads(fd.read(), VaultFile)

    password = getpass("Aegis vault password: ")

    with args.outfile as fd:
        ...

    return 0
