#!/usr/bin/env python
# exceptions.py


class EOF(Exception):
    pass

class TooManyPublicKeys(Exception):

    def __str__(self):
        return "More than one Public Key detected"

class UnknownSignatureVersion(Exception):

    def __init__(self, sig):
        self.sig = sig

    def __str__(self):
        return "Signature version %s not in (3, 4)" % self.sig
