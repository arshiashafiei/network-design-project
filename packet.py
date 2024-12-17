import random


class IP_Packet:
    def __init__(self, source_ip, destination_ip, payload=None):
        self.version = bin(4)[2:].zfill(4)
        self.header_length = bin(5)[2:].zfill(4)
        self.type_of_service = bin(0)[2:].zfill(8)
        self.total_length = None
        self.id = bin(random.randint(1, 65535))[2:].zfill(16)
        self.flags = bin(0)[2:].zfill(3)  # Reserved, DF, MF flags
        self.fragment_offset = bin(0)[2:].zfill(13)  # Fragment offset
        self.time_to_live = bin(64)[2:].zfill(8)
        self.protocol = bin(17)[2:].zfill(8)
        self.header_checksum = bin(0)[2:].zfill(16)
        self.source_ip = self.ip_to_bin(source_ip)
        self.destination_ip = self.ip_to_bin(destination_ip)
        self.payload = payload if payload else ""

        # Calculate total length (header + payload)
        self.total_length = bin(20 + (len(self.payload) // 8))[2:].zfill(16)

        # Placeholder for checksum computation
        # self.header_checksum = bin(self.calculate_checksum())[2:].zfill(16)

    @staticmethod
    def ip_to_bin(ip):
        """Convert dotted-decimal IP address to binary string."""
        return ''.join(bin(int(octet))[2:].zfill(8) for octet in ip.split('.'))

    @staticmethod
    def bin_to_ip(ip_bin):
        """Convert binary string to dotted-decimal IP address."""
        return '.'.join(str(int(ip_bin[i:i+7], 2)) for i in range(0, 32, 8))

    def calculate_checksum(self):
        """Dummy checksum calculation."""
        header = (
            self.version
            + self.header_length
            + self.type_of_service
            + self.total_length
            + self.id
            + self.flags
            + self.fragment_offset
            + self.time_to_live
            + self.protocol
            + self.source_ip
            + self.destination_ip
        )

        # Split header into 16-bit chunks
        checksum = 0
        for i in range(0, len(header), 16):
            checksum += int(header[i:i+16], 2)

        # Add overflow bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        return ~checksum & 0xFFFF

    def get_packet_bits(self):
        """Return the bit representation of the packet as bytes."""
        header_bits = (
            self.version
            + self.header_length
            + self.type_of_service
            + self.total_length
            + self.id
            + self.flags
            + self.fragment_offset
            + self.time_to_live
            + self.protocol
            + self.header_checksum
            + self.source_ip
            + self.destination_ip
        )
        payload_bits = ''.join(bin(ord(char))[2:].zfill(8) for char in self.payload)
        bit_string = header_bits + payload_bits
        # utf8_string = bytes(int(bit_string[i : i + 8], 2) for i in range(0, len(bit_string), 8)).decode("utf-8")
        return bytes(int(bit_string[i : i + 8], 2) for i in range(0, len(bit_string), 8))
    
    @classmethod
    def deserialize(cls, packet_bytes):
        """Deserialize a bytes object into an IP_Packet object."""
        # Convert bytes to bit string
        bit_string = bin(int(packet_bytes, base=16))
        # bit_string = ''.join(f'{byte:08b}' for byte in packet_bytes)

        # Parse header fields
        version = bit_string[0:4]
        header_length = bit_string[4:8]
        type_of_service = bit_string[8:16]
        total_length = int(bit_string[16:32], 2)
        packet_id = bit_string[32:48]
        flags = bit_string[48:51]
        fragment_offset = bit_string[51:64]
        time_to_live = bit_string[64:72]
        protocol = bit_string[72:80]
        header_checksum = bit_string[80:96]
        source_ip = cls.bin_to_ip(bit_string[96:128])
        destination_ip = cls.bin_to_ip(bit_string[128:160])

        # Extract payload (remaining bits)
        payload_bits = bit_string[160:total_length * 8]
        payload = ''.join(chr(int(payload_bits[i:i+8], 2)) for i in range(0, len(payload_bits), 8))

        # Create a new IP_Packet object
        packet = cls(source_ip, destination_ip, payload)
        packet.version = version
        packet.header_length = header_length
        packet.type_of_service = type_of_service
        packet.total_length = bin(total_length)[2:].zfill(16)
        packet.id = packet_id
        packet.flags = flags
        packet.fragment_offset = fragment_offset
        packet.time_to_live = time_to_live
        packet.protocol = protocol
        packet.header_checksum = header_checksum

        return packet

    def __str__(self):
        """User-friendly representation of the packet."""
        return (f"IP Packet: Version=4, Source={self.bin_to_ip(self.source_ip)}, "
                f"Destination={self.bin_to_ip(self.destination_ip)}, Payload='{self.payload}', "
                f"TTL={int(self.time_to_live, 2)}")

    def __repr__(self):
        """Technical representation of the packet."""
        return (f"IP_Packet(source_ip='{self.bin_to_ip(self.source_ip)}', "
                f"destination_ip='{self.bin_to_ip(self.destination_ip)}', "
                f"payload='{self.payload}')")
