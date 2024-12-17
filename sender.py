import threading
import time

from scapy.all import sniff, Raw, sendp
from scapy.layers.l2 import Ether
from packet import IP_Packet
from colors import bcolors


def send_packet(filename, source_ip, destination_ip):
    with open(filename, 'r') as file:
        for line in file:
            inner_ip_packet = IP_Packet(destination_ip, source_ip, line.encode("utf-8"))
            # print("Inner: " + str(inner_ip_packet))

            outer_ip_packet = IP_Packet(source_ip, destination_ip, inner_ip_packet.serialize())
            print(bcolors.OKBLUE + "Packet sent: " + str(outer_ip_packet) + bcolors.OKBLUE)

            sendp(Ether(src="08:00:27:c7:e1:36", dst="08:00:27:bb:7a:67") / Raw(load=outer_ip_packet.serialize()), iface="vboxnet0")
            time.sleep(1)


def process_received_packets(packet, expected_src_ip):
    try:
        ip_packet = IP_Packet.deserialize(packet[Ether][Raw].load)
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        raise
    print(f"Processing packet: {ip_packet}")
    if ip_packet.destination_ip == expected_src_ip:
        print(bcolors.OKGREEN + f"Received line: {ip_packet.payload.decode()}" + bcolors.OKGREEN)


def listener(interface, expected_src_ip):
    while True:
        Captured = sniff(iface=interface, count=1)
        # print(f"Captured packet: {Captured}")

        process_received_packets(Captured[0], expected_src_ip)


def start_receiver(interface, expected_src_ip):
    receiver_thread = threading.Thread(target=listener, args=(interface, expected_src_ip), daemon=True)
    receiver_thread.start()


def main():
    mode = input(bcolors.OKCYAN + "Hello :(To start the program enter '1'): " + bcolors.OKCYAN)
    filename = "send.txt"
    source_ip = "192.168.59.103"
    destination_ip = "192.168.59.102"
    interface = "vboxnet0"
    start_receiver(interface, source_ip)

    if mode == "1":
        send_packet(filename, source_ip, destination_ip)

        # Keep the main thread alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print(bcolors.FAIL + "Receiver stopped." + bcolors.FAIL)


if __name__ == "__main__":
    main()
