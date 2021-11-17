import os
import os
import struct
from scapy.all import *

def sendImage(chunks, ip):
    for n in range(len(chunks)):
        ping = IP(dst=ip)/ICMP()/chunks[n]
        print(ping)
        send(ping)

def getImageFromDisk(filename):
    with open(filename, "rb") as reader:
        image = reader.read()
        chunk = []
        #interval = 1000
        interval = 1500 - 20 - 8 - 4
        for n in range(0, len(image), interval):
            chunk.append(image[n:n + interval])

        for n in range(len(chunk)):
            chunk[n] = struct.pack(">I", n) + chunk[n]
            #print(chunk[n])
            #chunk.sort()
        chunk.append(b'\x7f\xff\xff\xff')
        #print (chunk[len(chunk)-1])
        return chunk

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 client.py ServerIp file")
    else:
        ip = str(sys.argv[1])
        filename = sys.argv[2]
        chunks = getImageFromDisk(filename)
        sendImage(chunks, ip)

if __name__ == "__main__":
    main()
