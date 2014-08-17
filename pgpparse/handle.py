#!/usr/bin/env python3
# handle.py

from io import BytesIO

from pgpparse.exceptions import EOF


# class Handle(BytesIO):
class Handle:
    """
    A small abstraction that just adds a method returning bytes interpreted
    as an int. Use with caution and against utmost prejudice.
    """
    def __init__(self, buf, *args, **kwargs):
        self.io = BytesIO(buf, *args, **kwargs)

    def read(self, size):
        content = self.io.read(size)
        if not content or len(content) < size:
            raise EOF("EOF at %s" % hex(self.io.tell()))
        return content

    def read_int(self, n, byteorder="big"):
        # content = self.read(n)
        content = self.io.read(n)
        if not content or len(content) < n:
            raise EOF("EOF at %s" % hex(self.io.tell()))

        return int.from_bytes(content, byteorder=byteorder)
