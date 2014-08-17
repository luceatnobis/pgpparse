#!/usr/bin/env python3

from pgpparse import public_key

public_algorithms = {
    1: public_key.RSA_Public,
    16: public_key.Elgamal_Public,
    17: public_key.DSA_Public
}

signature_algorithms = {
    1: public_key.RSA_Signature
}

signature_class_attrs = {
    2: "creation_time",
    3: "signature_expiration_time",
    9: "key_expiration_time",
    11: "preferred_symmetric_algorithms",
    27: "key_flags",
    255: "trash_packet",
}
