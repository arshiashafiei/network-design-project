from scapy.all import IP, send, sniff, Raw, sendp
from scapy.layers.l2 import Ether
from packet import IP_Packet
import threading
import time


def read_file_and_send(filename, source_ip, destination_ip):
    with open(filename, 'r') as file:
        for line in file:
            inner_ip_packet = IP_Packet(destination_ip, source_ip, line.encode("utf-8"))
            print("Inner: " + str(inner_ip_packet))
            # Create the inner IP packet
            # inner_ip_packet =  / Raw(load=line.encode('utf-8'))

            # Create the outer IP packet
            # outer_ip_packet = IP(src=source_ip, dst=destination_ip) / inner_ip_packet
            outer_ip_packet = IP_Packet(source_ip, destination_ip, inner_ip_packet.serialize())
            print("Packet sent: " + str(outer_ip_packet))

            # Send the packet to the Dest.
            sendp(Ether() / Raw(load=outer_ip_packet.serialize()), iface="vboxnet0")
            time.sleep(1)


def receive_and_process_packets(packet, expected_src_ip):
    try:
        ip_packet = IP_Packet.deserialize(packet[Ether][Raw].load)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
    print(f"Processing packet: {ip_packet}")
    if ip_packet.destination_ip == expected_src_ip:
        print(f"Received line: {ip_packet.payload.decode()}")
    else:
        print("Packet dst IP is wrong! :/")

        # outer_payload = packet[IP].payload
        # if IP in outer_payload:
        #     inner_ip_packet = outer_payload[IP]
        #     if Raw in inner_ip_packet:
        #         payload_content = inner_ip_packet[Raw].load.decode('utf-8')
        #         print(f"Received line: {payload_content}")


def listener(interface, expected_src_ip):
    while True:
        Captured = sniff(iface=interface, count=1)
        print(f"Captured packet: {Captured}")

        receive_and_process_packets(Captured[0], expected_src_ip)


def start_receiver(interface, expected_src_ip):
    receiver_thread = threading.Thread(target=listener, args=(interface, expected_src_ip), daemon=True)
    receiver_thread.start()


def main():
    mode = input("Select mode(1: sender, 2: Receiver): ")
    filename = "send.txt"
    source_ip = "192.168.59.103"
    destination_ip = "192.168.59.102"
    interface = "vboxnet0"
    start_receiver(interface, source_ip)

    if mode == "1":
        read_file_and_send(filename, source_ip, destination_ip)

        # Keep the main thread alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("Receiver stopped.")

    elif mode == "2":
        start_receiver(interface, destination_ip)

        # Keep the main thread alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("Receiver stopped.")


if __name__ == "__main__":
    main()
