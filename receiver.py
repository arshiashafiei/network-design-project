from scapy.all import IP, send, sniff, Raw
import threading


def read_file_and_send(filename, source_ip, destination_ip):
    with open(filename, 'r') as file:
        for line in file:
            # Create the inner IP packet
            inner_ip_packet = IP(src=source_ip, dst=destination_ip) / Raw(load=line.encode('utf-8'))

            # Create the outer IP packet
            outer_ip_packet = IP(src=destination_ip, dst=source_ip) / inner_ip_packet

            # Send the packet to the destination
            send(outer_ip_packet)


def receive_and_process_packets(packet):
    if IP in packet:
        outer_payload = packet[IP].payload
        if IP in outer_payload:
            inner_ip_packet = outer_payload[IP]
            if Raw in inner_ip_packet:
                payload_content = inner_ip_packet[Raw].load.decode('utf-8')
                print(f"Received payload: {payload_content}")

                # Send the same payload back to the sender
                response_packet = IP(src=packet[IP].dst, dst=packet[IP].src) / Raw(load=inner_ip_packet[Raw].load)
                send(response_packet)
                print(f"Response sent: {inner_ip_packet[Raw].load.decode('utf-8')}")


def listener(interface, source_ip):
    def process_response_packet(packet):
        if IP in packet and Raw in packet:
            payload_content = packet[Raw].load.decode('utf-8')
            print(f"Response payload received: {payload_content}")

    sniff(iface=interface, filter=f"ip and src {source_ip}",
          prn=lambda packet: (receive_and_process_packets(packet), process_response_packet(packet)))


def start_receiver(interface, source_ip):
    receiver_thread = threading.Thread(target=listener, args=(interface, source_ip), daemon=True)
    receiver_thread.start()


def main():
    mode = input("Select mode (1: Sender, 2: Receiver): ")

    filename = "send.txt"
    source_ip = input("Enter source IP: ")
    destination_ip = input("Enter destination IP: ")
    interface = input("Enter network interface: ")

    if mode == "1":
        read_file_and_send(filename, source_ip, destination_ip)
    elif mode == "2":
        print("Starting receiver...")
        start_receiver(interface, destination_ip)

        # Keep the main thread alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("Receiver stopped.")


if __name__ == "__main__":
    main()
