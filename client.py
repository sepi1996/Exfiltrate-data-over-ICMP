import os
import struct
from scapy.all import *

def sendImage(chunks):
    for n in range(len(chunks)):
        ping = IP(dst="172.18.0.2")/ICMP()/chunks[n]
        print(ping)
        send(ping)

def getImageFromDisk():
    with open("a.txt", "rb") as reader:
        image = reader.read()
        chunk = []
        interval = 4
        for n in range(0, len(image), interval):
            chunk.append(image[n:n + interval])

        for n in range(len(chunk)):
            chunk[n] = struct.pack(">I", n) + chunk[n]
            chunk.sort()
            return chunk

def main():
    chunks = getImageFromDisk()
    sendImage(chunks)

if __name__ == "__main__":
    main()