import random
import socket
import struct


class IP_Packet:
    def __init__(self, source_ip, destination_ip, payload=None):
        self.version = 4
        self.header_length = 5
        self.type_of_service = 0
        self.total_length = 0
        self.id = random.randint(1, 65535)
        self.flags = 2
        self.fragment_offset = 0
        self.time_to_live = 128
        self.protocol = 6
        self.header_checksum = 0
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        if payload is None:
            payload = b''
        self.payload = payload
        self.total_length = 20 + len(self.payload)
        self.header_checksum = 0

        # Placeholder for checksum computation
        # self.header_checksum = bin(self.calculate_checksum())[2:].zfill(16)

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

    def _pack_header(self, checksum):
        version_ihl = (self.version << 4) + self.header_length
        flags_fragment = (self.flags << 13) + self.fragment_offset
        source_ip = socket.inet_aton(self.source_ip)
        destination_ip = socket.inet_aton(self.destination_ip)
        
        return struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            self.type_of_service,
            self.total_length,
            self.id,
            flags_fragment,
            self.time_to_live,
            self.protocol,
            checksum,
            source_ip,
            destination_ip
        )

    def serialize(self):
        """
        Serialize the IP packet into bytes for sending over the network.
        """
        header = self._pack_header(self.header_checksum)
        return header + self.payload

    @classmethod
    def deserialize(cls, data):
        """
        Deserialize bytes into an IP_Packet object.
        """
        header = data[:20]  # First 20 bytes are the header
        payload = data[20:]  # Remaining bytes are the payload
        
        unpacked = struct.unpack('!BBHHHBBH4s4s', header)

        packet =  cls(
            source_ip=socket.inet_ntoa(unpacked[8]),
            destination_ip=socket.inet_ntoa(unpacked[9]),
            payload=payload
        )
        packet.id = unpacked[3]
        return packet

    def __str__(self):
        """User-friendly representation of the packet."""
        return (f"IP Packet: Version=4, Source={(self.source_ip)}, "
                f"Destination={(self.destination_ip)}, Payload='{self.payload}', "
                f"TTL={self.time_to_live}")

    def __repr__(self):
        """Technical representation of the packet."""
        return (f"IP_Packet(source_ip='{(self.source_ip)}', "
                f"destination_ip='{(self.destination_ip)}', "
                f"payload='{self.payload}')")
