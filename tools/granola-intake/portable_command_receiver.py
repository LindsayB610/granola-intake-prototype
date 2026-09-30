#!/usr/bin/env python3
"""Runnable reference receiver for an owner-configured local handoff command.

Replace this command with the owner's orchestrator launcher when ready. It
demonstrates the exact stdin and private receipt contract without messaging a
desktop chat or performing downstream work.
"""
import argparse
import json
import os
import sys

from portable_command_handoff import load_config, write_receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    request = json.load(sys.stdin)
    write_receipt(load_config(args.config), request)


if __name__ == "__main__":
    main()
