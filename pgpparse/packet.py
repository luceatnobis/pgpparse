#!/usr/bin/env python3
# packets.py

import hashlib

from datetime import datetime as dt

from pgpparse import data
from pgpparse import signature
from pgpparse import exceptions

from pgpparse.funcs import bytes_for_int, mash_to_bytes, _check_new_packet


class Generic_Packet:
    """
    This is a class that simply describes a generic package, it does not have
    information about packet contents or types. It merely adheres to the
    common length description and is only used to derive meta information from
    packets.
    """

    def __init__(self, header, handle):
        """
        This is only valid if we're dealing with an old package, indeterminate
        lengths are neither supported nor recommended for use.

        See Section 4.2.1 (http://tools.ietf.org/html/rfc4880#section-4.2.1)
        """

        self._new_packet_indicator_byte_len = 1
        self._packet_header_cancel_for_len_len = 0x03
        self._packet_header_cancel_for_packet_type = 0x3c

        self.header = header
        self.handle = handle

        self.new_packet = _check_new_packet(self.header)
        if self.new_packet:
            self.len_length_field, self.body_length = self._get_len_new()
        else:
            self.len_length_field, self.body_length = self._get_len_old()

        self.body_length_bytes = self.body_length.to_bytes(2, "big")
        self.size = bytes_for_int(header) + (
            self.len_length_field + self.body_length)

    def _get_len_new(self):
        indicator_byte = self.handle.read_int(
            self._new_packet_indicator_byte_len)

        if indicator_byte < 192:
            raise NotImplementedError
        elif indicator_byte >= 192 and indicator_byte <= 223:
            raise NotImplementedError
        elif indicator_byte == 255:
            length_octs = 4
            body_length = self.handle.read_int(length_octs)

        len_length_octs = length_octs + self._new_packet_indicator_byte_len

        return [len_length_octs, body_length]

    def _get_len_old(self):
        len_length_field_octs = [1, 2, 4]  # section 4.2.

        len_length = self._get_len_length(self.header)

        if len_length == 3:
            raise NotImplementedError("Indeterminate length not supported")

        len_length_octs = len_length_field_octs[len_length]
        body_length = self.handle.read_int(len_length_octs)

        return [len_length_octs, body_length]

    def _get_len_length(self, header):
        """
        We need the first two bytes, so we'll & with 3.
        """
        return header & self._packet_header_cancel_for_len_len


class Trash_Packet(Generic_Packet):
    """
    This class describes a packet we do not care to parse or store. It simply
    serves to set the position indicator to *after* the packet via read.
    """
    def __init__(self, header, handle):
        super().__init__(header, handle)
        self.packet_type = 0  # indicating its forbidden
        handle.read(self.body_length)


class Signature_Packet(Generic_Packet):
    """
    I feel like quite a bit of explaining is required here.

    A signature packet is both a bit complex as well as partially unspecified.
    It can have two versions, V3 and V4. To make a long story short, I decided
    for an implementation based on metaclasses, that is, template classes that
    merely return the right class so that the corrrect class is instantiated.

    I ran into problems with this; to do metaclasses you usually override the
    __new__ method at which you can return another object. That is not possibe
    with the __init__ method. Signature_Packet inherits methods for things that
    every packet type must have from Generic_Packet. For some reason, Python
    regards the base class as a metaclass as well if you write the child class
    as a metaclass. This lead to every other packet type requiring to have a
    self object passed around. A little too much effort for my taste.

    Eventually I decided for a different process. Instead of inheriting from
    a class higher in the hierarchy, the Signature_Packet would call the con-
    structors of the child classes. This does not eliminate the need for a self
    object to be passed to the constructor, but it limits it to an overseeable
    extent. This is the reason why Signature_Packet_V4 does not inherit methods
    and why its not possible for these classes to have methods; they are not
    instantiated, but rather the sub-constructor is called on the self method.

    Its a bastardisation really.

    Also, V3 signatures are not implemented. If you use them I pity you. You
    poor sod.
    """

    def __init__(self, header, handle):
        self.subpackets = []
        super().__init__(header, handle)

        sig_version_field_len = 1
        version = handle.read_int(sig_version_field_len)

        signature_types = {
            3: signature.Signature_Packet_V3,
            4: signature.Signature_Packet_V4
        }
        try:
            signature_types[version].__init__(self, header, handle)
        except ValueError:
            return exceptions.UnknownSignatureVersion(version)

    def expired(self, now=None):
        assert self.version == 4  # not sure how it works with ver 3 lol
        if hasattr(self, "key_expiration_time"):  # no exp time, no expiration
            # create time object for point that key expires
            exp_dt = dt.fromtimestamp(self.creation_time.timestamp +
                                      self.key_expiration_time.seconds)

            if type(now) is not dt:  # no datetime object, includes None))
                now = dt.now()
            return exp_dt <= now  # do actual comparison
        return False  # apparently, it can't expire.


class Public_Key_Packet(Generic_Packet):
    """
    This is just a public key container, it contains
        - a length which is to be determined, 1, 2 and 4 byte are supported
        - a version number (one byte with value 4)
        - unix timestamp of the key creation, 4 byte
        - an algorithm marker, one byte
    """
    def __init__(self, header, handle):
        super().__init__(header, handle)  # call constructor of base class
        self.packet_tag = 6

        # definitions of field lengths in byte
        algo_field_len = 1
        version_field_len = 1
        timestamp_field_len = 4

        self.version = handle.read_int(version_field_len)
        if self.version != 4:  # TODO: implement version 3 keys
            raise Exception("Invalid version number at", hex(handle.io.tell()))

        self.timestamp = handle.read_int(timestamp_field_len)
        self.algorithm = handle.read_int(algo_field_len)

        self.key_material = data.public_algorithms[self.algorithm](handle)
        self.fingerprint = self._create_fingerprint()

    def _create_fingerprint(self):
        """
        This function creates a version 4 fingerprint. See Section 12.2.
        """
        header = 0x99  # regardless of the actual header, for subkeys

        packet = mash_to_bytes([
            header, self.body_length_bytes, self.version, self.timestamp,
            self.algorithm]) + self.key_material.to_bytes()

        return hashlib.sha1(packet).hexdigest()


class Public_Subkey_Packet(Public_Key_Packet):
    """
    Subkeys are identical to actual keys, so this is basically a copy of the
    actual Public_Key_Packet, but they warrant differentiation because they
    have different packet tags. For example.
    """

    def __init__(self, header, handle):
        super().__init__(header, handle)
        self.packet_tag = 14


class User_Attribute_Packet(Generic_Packet):

    def __init__(self, header, handle):
        pass
