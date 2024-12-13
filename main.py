from scapy.all import IP, send, sniff, Raw
import threading


def read_file_and_send(filename, source_ip, destination_ip):
    with open(filename, 'r') as file:
        for line in file:
            # Create the inner IP packet
            inner_ip_packet = IP(src=source_ip, dst=destination_ip) / Raw(load=line.encode('utf-8'))

            # Create the outer IP packet
            outer_ip_packet = IP(src=destination_ip, dst=source_ip) / inner_ip_packet

            # Send the packet to the Dest.
            send(outer_ip_packet)


def receive_and_process_packets(interface, expected_src_ip):
    if IP in packet and packet[IP].src == expected_src_ip:
        outer_payload = packet[IP].payload
        if IP in outer_payload:
            inner_ip_packet = outer_payload[IP]
            if Raw in inner_ip_packet:
                payload_content = inner_ip_packet[Raw].load.decode('utf-8')
                print(f"Received line: {payload_content}")


def listener(interface, expected_src_ip):
    Captured = sniff(iface=interface, filter=f"ip src {expected_src_ip}", count=1)
    print(f"Captured packet: {Captured}")

    return Captured


def start_receiver(interface, expected_src_ip):
    receiver_thread = threading.Thread(target=listener, args=(interface, expected_src_ip), daemon=True)
    receiver_thread.start()


def main():

    if args.mode == "1":
        if not args.filename:
            parser.error("Filename is required in send mode.")
        read_file_and_send(args.filename, args.dest_ip, args.intermediary_ip)
    elif args.mode == "2":
        start_receiver(args.interface, args.dest_ip)

        # Keep the main thread alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("Receiver stopped.")


if __name__ == "__main__":
    main()
