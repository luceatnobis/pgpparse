#!/usr/bin/env python3

from datetime import datetime as dt

from pgpparse import packet
from pgpparse import exceptions

from pgpparse.funcs import _check_new_packet
from pgpparse.handle import Handle


class Key:
    """
    A key is actually more a collection of PGP packets than a "Key" itself,
    therefore, I will regard this type simply as a collection of packets, with
    the public key packet being singled out for the purposes of the ZNC plugin.

    For general reference, see RFC 44880 (http://tools.ietf.org/html/rfc4880)
    """
    def __init__(self, byte_str):
        self._packet_header_len = 1
        self._packet_header_checkbit = 0x80
        self._packet_header_cancel_for_packet_type_old = 0x3c
        self._packet_header_cancel_for_packet_type_new = 0xc0

        self.signatures_sign = list()
        self.signatures_crypt = list()

        handle = Handle(byte_str)

        # http://tools.ietf.org/html/rfc4880#section-4.3
        tag_packet_map = {
            2: ["signature", packet.Signature_Packet],
            6: ["public_key", packet.Public_Key_Packet],
            14: ["public_subkey", packet.Public_Subkey_Packet],
            17: ["user_attribute", packet.User_Attribute_Packet]
        }

        while True:
            try:
                header = handle.read_int(self._packet_header_len)
            except exceptions.EOF:
                break

            packet_type = self._parse_packet_header(header, handle)
            class_var, packet_class = tag_packet_map.get(
                packet_type, ["trash", packet.Trash_Packet])

            packet_obj = packet_class(header, handle)
            if hasattr(self, class_var):
                getattr(self, class_var).append(packet_obj)
            else:
                setattr(self, class_var, [packet_obj])

        for sig in self.signature:
            # find signatures that can be used for encryption
            if sig.key_flags.crypt_comm or sig.key_flags.crypt_stor:
                self.signatures_crypt.append(sig)

            # find signatures that can be used for signing
            if sig.key_flags.sign_data:
                self.signatures_sign.append(sig)


    def _parse_packet_header(self, header, handle):
        """
        Here we will do a few checks and return the packet type that follows
        this byte as an integer.
        """
        # Highest bit set?
        if not self._check_valid_packet(header):
            raise Exception("Not a valid packet: highest bit not set: %s" %
                            hex(header))

        # Lets find out if its an old or a new packet
        if _check_new_packet(header):
            packet_type = self._get_new_packet_type(header)
        else:  # we have an old packet
            packet_type = self._get_old_packet_type(header)
        return packet_type

    def _check_valid_packet(self, header):
        """
        Check if the highest bit isn't set.
        """
        return bool(header & self._packet_header_checkbit)

    def _get_old_packet_type(self, header):
        """
        Old format packets contain:

            Bits 5-2 -- packet tag
            Bits 1-0 -- length-type

        We need to kill bits 7, 6, 2 and 1 so 00111100 can remain, which turns
        out to be 0x3c or 60 to be &'ed with the packet header.
        """
        return (header & self._packet_header_cancel_for_packet_type_old) >> 2

    def _get_new_packet_type(self, header):
        """
        New format packets contain:

            Bits 5-0 -- packet tag

        We just kill bits 7 and 6, so that 00111111 can remain. The mask for
        this is 0xc0.
        """
        return (header & self._packet_header_cancel_for_packet_type_new)

    def expired(self):
        """
        Just a small wrapper function to figure out if anything in the key
        has been expired. PGP is very modular, and if not through the gnupg
        program, it is possible by key modification to have a key that has
        expired with a signature that has not expired.

        Returns True on any expiration.
        """
        now = dt.now()
        return any(x.expired(now=now) for x in self.signatures_crypt +
                   self.signatures_sign)
