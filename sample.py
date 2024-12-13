# from scapy.all import *
from scapy.layers.l2 import Ether
import time
import math


SRC = "0a:00:27:00:00:1d"
DST = "08:00:27:04:43:ea"


class Header:
    def __init__(self, ack, nack, seq, msg_len=0):
        self.ack = ack
        self.nack = nack
        self.seq = seq
        self.len = msg_len

    def __str__(self):
        return f"{self.ack} {self.nack} {self.len} {self.seq}"

    def __repr__(self):
        return self.__str__()


class Packet:
    def __init__(self, payload=None):
        self.protocol = "UEP"
        if payload is None:
            payload = ""
        self.payload = payload
        self.frame_count = math.ceil(len(payload) / 1400)
        self.frames = []
        self.create_frames()

    def create_frames(self):
        for i in range(self.frame_count):
            header = Header(ack=0, nack=0, seq=i, msg_len=self.frame_count)
            self.frames.append(f"{self.protocol}\r\n{header.__str__()}\r\n{self.payload[i*1400:(i+1)*1400]}\r\n")

    def create_ack(self, seq):
        header = Header(ack=1, nack=0, seq=seq)
        return f"{self.protocol}\r\n{header.__str__()}\r\n"

    def create_nack(self, seq):
        header = Header(ack=0, nack=1, seq=seq)
        return f"{self.protocol}\r\n{header.__str__()}\r\n"

    def send_packet(self, src, dst, iface):
        for frame in self.frames:
            self.send_frame(src, dst, iface, frame)
            res = None
            loop = True
            while loop:
                try:
                    res = sniff(iface=iface, count=1, timeout=0.1)
                    if len(res) == 0:
                        self.send_frame(src, dst, iface, frame)
                        continue
                    res_payload = res[0].load.decode("utf-8")
                    # if payload starts with UEP
                    if res_payload[:3] == "UEP":
                        print(res[0])
                        print(res_payload)
                        header, payload = self.deserialize(res_payload)
                        if header.ack == 1:
                            loop = False
                            break
                    continue
                except:
                    continue

    @staticmethod
    def send_frame(src, dst, iface, frame):
        eth_frame = Ether(src=src, dst=dst)
        pkt = eth_frame / frame

        pkt.show()

        sendp(pkt, iface=iface)
        print("Frame sent!")

    @staticmethod
    def send_ack_nack(src, dst, iface, frame):
        eth_frame = Ether(src=src, dst=dst)
        pkt = eth_frame / frame

        pkt.show()

        sendp(pkt, iface=iface)
        print("Frame sent!")

    @staticmethod
    def deserialize_header(data):
        header_fields = data.split(" ")
        header = Header(
            ack=int(header_fields[0]),
            nack=int(header_fields[1]),
            msg_len=int(header_fields[2]),
            seq=int(header_fields[3]))
        return header

    def deserialize(self, data):
        data = data.split("\r\n")
        header = self.deserialize_header(data[1])

        if header.ack != "1" and header.nack != "1":
            self.payload += data[2]
        return header, data[2]

    def receive_packet(self, iface):
        while True:
            frames = sniff(iface=iface, count=1)
            try:
                frame = frames[0]
                frame_payload = frame.load.decode("utf-8")
                expected_seq = 0
                # if payload starts with UEP
                if frame_payload[:3] == "UEP":
                    print(frame)
                    print(frame_payload)
                    header, payload = self.deserialize(frame_payload)
                    time.sleep(0.01)
                    self.send_ack_nack(src=SRC, dst=DST, iface=iface, frame=self.create_ack(header.seq))
                    if header.seq == header.len - 1:
                        break
                else:
                    continue
            except:
                continue



def main():
    mode = int(input("Enter mode\n1. send\n2. receive:\n"))
    if mode == 1:
        # payload = input("Enter payload: ")
        payload = "s" * 2000
        my_packet = Packet(payload=payload)
        my_packet.send_packet(src=SRC, dst=DST, iface="VirtualBox Host-Only Network")
    elif mode == 2:
        my_packet = Packet()
        my_packet.receive_packet(iface="VirtualBox Host-Only Network")


if __name__ == "__main__":
    main()
