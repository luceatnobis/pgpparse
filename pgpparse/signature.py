#!/usr/bin/env python3
# signature.py

from pgpparse import data
from pgpparse import exceptions

from pgpparse.handle import Handle


class Signature_Sub_Packet:

    def __init__(self, handle):

        signature_packets = {
            2: Signature_Creation_Time,
            3: Signature_Signature_Expiration_Time,
            9: Signature_Key_Expiration_Time,
            11: Signature_Preferred_Symmetric_Algorithms,
            27: Signature_Key_flags,
        }
        self.packet_type_size = 1
        self.length_size, self.body_len = self._get_total_length(handle)
        self.packet_type = handle.read_int(self.packet_type_size)

        packet_class = signature_packets.get(
            self.packet_type, Signature_Trash_Packet)

        # lets do the bastardisation
        packet_class.__init__(self, handle,
                              **{'body_len': self.body_len})
        self.size = self.length_size + self.body_len + self.packet_type_size

    def _get_total_length(self, handle):  # See Section 5.2.3.1
        length_indicator_size = 1
        length_indicator = handle.read_int(length_indicator_size)

        if length_indicator < 192:
            add_bytes_to_read = 0
            body_len = length_indicator - self.packet_type_size
        elif length_indicator >= 192 and length_indicator < 255:
            add_bytes_to_read = 1
            second_octet = handle.read_int(add_bytes_to_read)
            body_len = ((length_indicator - 192) << 8) + second_octet + 192
        elif length_indicator == 255:
            add_bytes_to_read = 4
            body_len = handle.read_int(add_bytes_to_read)
        else:
            raise Exception("U WOT")

        length_field_size = length_indicator_size + add_bytes_to_read
        return [length_field_size, body_len]


class Signature_Packet_V3:

    def __init__(self):
        raise NotImplementedError


class Signature_Packet_V4:

    def __init__(self, header, handle):
        sig_type_field_len = 1
        sig_public_key_field_len = 1
        sig_hash_algo_field_len = 1
        sig_hashed_subpackets_field_len = 2
        sig_unhashed_subpackets_field_len = 2
        sig_left_word_of_signed_hash_value_field_len = 2

        self.version = 4
        self.type = handle.read_int(sig_type_field_len)
        self.public_key_algo_id = handle.read_int(sig_public_key_field_len)
        self.hash_algo_id = handle.read_int(sig_hash_algo_field_len)

        self.hashed_subpackets_len = handle.read_int(
            sig_hashed_subpackets_field_len)

        # print("Starting at %s" % hex(handle.io.tell()))
        self.hashed_subpackets_data = handle.read(
            self.hashed_subpackets_len)

        subpacket_handle = Handle(self.hashed_subpackets_data)

        while True:
            try:
                subpacket = Signature_Sub_Packet(subpacket_handle)
                class_attr = data.signature_class_attrs.get(
                    subpacket.subpacket_type)
                setattr(self, class_attr, subpacket)
            except exceptions.EOF:
                break

        self.unhashed_subpackets_len = handle.read_int(
            sig_unhashed_subpackets_field_len)

        self.unhashed_subpackets_data = handle.read(
            self.unhashed_subpackets_len)

        self.left_word_of_signed_hash_value = handle.read(
            sig_left_word_of_signed_hash_value_field_len)

        self.algo = data.signature_algorithms[self.public_key_algo_id](handle)


class Signature_Trash_Packet:
    """
    A trash class to skip over unimplemented signature subpackets
    """
    def __init__(self, handle, **kwargs):
        self.subpacket_type = 0xFF
        # print("Found trash packet, reading", kwargs['body_len'])
        self.byte = handle.read(kwargs['body_len'])


class Signature_Creation_Time:  # Section 5.2.3.4

    def __init__(self, handle, **kwargs):
        self.subpacket_type = 2
        timestamp_size = 4

        self.timestamp = handle.read_int(timestamp_size)

class Signature_Signature_Expiration_Time:

    def __init__(self, handle, **kwargs):
        self.subpacket_type = 3
        time_field_size = 4

        self.seconds = handle.read_int(time_field_size)

class Signature_Key_Expiration_Time:  # See Section 5.2.3.6

    def __init__(self, handle, **kwargs):
        self.subpacket_type = 9
        time_field_size = 4

        self.seconds = handle.read_int(time_field_size)

class Signature_Preferred_Symmetric_Algorithms:

    def __init__(self, handle, **kwargs):
        self.subpacket_type = 11
        self.byte = handle.read(kwargs['body_len'])

class Signature_Key_flags:

    def __init__(self, handle, **kwargs):
        self.subpacket_type = 27
        flags = ["cert_keys", "sign_data", "crypt_comm", "crypt_stor",
                 "secret_share", "auth", "dummy", "shared_poss"]
    
        flag_bytes = kwargs['body_len']
        flag_byte = handle.read_int(flag_bytes)

        for i in range(flag_bytes * 8):
            if i == 6:  # 0x40 is not defined in 5.2.3.21
                continue
            try:
                setattr(self, flags[i], bool(flag_byte & (1 << i)))
            except IndexError:
                break
