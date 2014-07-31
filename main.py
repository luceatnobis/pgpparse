#!/usr/bin/env python3

# TODO: give much loving to lines of code or contract AIDS from local pet shop

import sys
import timeit

import pgpparse

def main():
    raw = sys.stdin.buffer.read()
    k = pgpparse.Key(raw)

if __name__ == "__main__":
    main()
