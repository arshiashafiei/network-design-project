from scapy.all import IP, send, sniff, sendp, Raw
from scapy.layers.l2 import Ether
import threading

from packet import IP_Packet


def receive_and_process_packets(packet, expected_src_ip):
    try:
        ip_packet = IP_Packet.deserialize(packet[Ether][Raw].load)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
    print(f"Processing packet: {ip_packet}")

    if ip_packet.destination_ip == IP_Packet.ip_to_bin(expected_src_ip):
        try:
            outer_payload = eval(ip_packet.payload)
            inner_ip_packet = IP_Packet.deserialize(outer_payload)
            
            response_packet = outer_payload
            print(response_packet.get_packet_bits())
            sendp(Ether() / Raw(load=response_packet.get_packet_bits()), iface="vboxnet0")
            print(f"Response sent: {inner_ip_packet}")
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise
    else:
        print("Packet dst IP is wrong! :/")

    

 


def listener(interface, expected_src_ip, expected_dst_ip):
    while True:
        Captured = sniff(iface=interface, count=1)
        print(f"Captured packet: {Captured}")

        receive_and_process_packets(Captured[0], expected_src_ip=expected_dst_ip)


def start_receiver(interface, expected_src_ip, expected_dst_ip):
    receiver_thread = threading.Thread(target=listener, args=(interface, expected_src_ip, expected_dst_ip), daemon=True)
    receiver_thread.start()


def main():
    print("Starting Receiver...")

    source_ip = "192.168.59.103"
    destination_ip = "192.168.59.102"
    interface = "vboxnet0"

    start_receiver(interface, source_ip, destination_ip)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Receiver stopped.")


if __name__ == "__main__":
    main()
