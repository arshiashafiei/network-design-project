import threading

from scapy.all import sniff, sendp, Raw
from scapy.layers.l2 import Ether
from packet import IP_Packet
from colors import bcolors


def receive_and_process_packets(packet, expected_src_ip):
    try:
        ip_packet = IP_Packet.deserialize(packet[Ether][Raw].load)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
    print(f"Processing packet: {ip_packet}")

    if ip_packet.destination_ip == expected_src_ip:
        try:
            outer_payload = ip_packet.payload
            inner_ip_packet = IP_Packet.deserialize(outer_payload)
            
            sendp(Ether() / Raw(load=inner_ip_packet.serialize()), iface="vboxnet0")
            print(bcolors.OKGREEN + f"Response sent: {inner_ip_packet}" + bcolors.OKGREEN)
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
