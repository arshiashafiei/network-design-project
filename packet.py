
class IP_Packet:
    def __init__(self, source_ip, destination_ip, payload=None):
        self.version = "0" + bin(4)[2:]
        self.header_length = bin(20)[2:]
        self.quality_of_service = bin(4)[2:]
        self.total_length = ""
        self.id = ""
        self.flags = ""
        self.fragment_offset = ""
        self.time_to_live = 128
        self.protocol = "MEO"
        self.checksum = 12
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        if payload is None:
            payload = ""
        self.payload = payload
        self.fragments = []
        self.create_frames()

    def generate_id():
        yield range(len(id))

class IP_Packet_2:
    def __init__(self, source_ip, destination_ip, payload=None):
        self.version = "0" + bin(4)[2:].zfill(3)  # IPv4
        self.header_length = bin(5)[2:].zfill(4)  # Header length in 32-bit words (5 * 4 = 20 bytes)
        self.type_of_service = bin(0)[2:].zfill(8)  # Default QoS
        self.total_length = None  # Total length in bytes, calculated later
        self.id = bin(0)[2:].zfill(16)  # Identification field
        self.flags = bin(0)[2:].zfill(3)  # Reserved, DF, MF flags
        self.fragment_offset = bin(0)[2:].zfill(13)  # Fragment offset
        self.time_to_live = bin(64)[2:].zfill(8)  # Default TTL value
        self.protocol = bin(6)[2:].zfill(8)  # Protocol (e.g., 6 = TCP)
        self.header_checksum = bin(0)[2:].zfill(16)  # Placeholder, checksum would normally be computed
        self.source_ip = self.ip_to_bin(source_ip)
        self.destination_ip = self.ip_to_bin(destination_ip)
        self.payload = payload if payload else ""

        # Calculate total length (header + payload)
        self.total_length = bin(20 + len(self.payload.encode()))[2:].zfill(16)

        # Placeholder for checksum computation
        self.header_checksum = bin(self.calculate_checksum())[2:].zfill(16)

    def ip_to_bin(self, ip):
        """Convert dotted-decimal IP address to binary string."""
        return ''.join(bin(int(octet))[2:].zfill(8) for octet in ip.split('.'))

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
        """Return the bit representation of the packet as a string."""
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
        return header_bits + payload_bits

# Example usage:
packet = IP_Packet("192.168.1.1", "192.168.1.2", payload="Hello")
print(packet.get_packet_bits())
