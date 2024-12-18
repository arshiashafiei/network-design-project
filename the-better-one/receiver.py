import threading

from scapy.all import IP, send, sniff


def receive_and_process_packets(packet, expected_src_ip):
    print(f"Processing packet: {packet}")
    if IP in packet:
        outer_payload = packet[IP].payload
        if IP in outer_payload:
            if outer_payload[IP].dst == expected_src_ip:
                # Send the same payload back to the sender
                response_packet = outer_payload
                send(response_packet)
                print(f"Response sent: {response_packet}")
    else:
        print("Packet is not the one we want! :/")


def listener(interface, expected_src_ip, expected_dst_ip):
    while True:
        Captured = sniff(iface=interface, filter=f"ip src {expected_src_ip} and ip dst {expected_dst_ip}", count=1)
        print(f"Captured packet: {Captured}")

        receive_and_process_packets(Captured[0], expected_src_ip)


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
