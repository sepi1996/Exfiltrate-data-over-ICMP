import socket
import struct
import os
#ICMP_CODE = socket.getprotobyname('icmp')

def processData(chunk):
    print(chunk)
    chunk.sort()
    for n in range(len(chunk)):
        chunk[n] = chunk[n][4:]
    exit(0)


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    chunk = []
    while True:
        raw_data, addr = conn.recvfrom(65536)
        print(raw_data)
        dest_mac, src_mac, eth_proto, data = ether_frame(raw_data)
        print(f'Ether Frame:')
        print(f'\tDest mac addres {dest_mac}')
        print(f'\tSource mac addres {src_mac}')
        print(f'\tProto {eth_proto}')

        if eth_proto == 8:
            (version, h_l, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'Ipv4 packet')
            print(f'\t Version: {version}, Header Lenght: {h_l}, TTL: {ttl}')
            print(f'\t Protocol: {proto}, Source: {src}, Target {target}')

            if proto == 1:
                i_t, code, check, data = icmp_packet(data)
                print(f'ICMP packet')
                print(f'\t type: {i_t}, code: {code}, checksum: {check}')
                print(f'\t data: {data}')
                print("\n")
                if int(i_t) == 8:
                    chunk.append(data)
                    #print("CHUNK")
                    #print(chunk)
                    if data == b'\x7f\xff\xff\xff':
                        processData(chunk)
                        
def ether_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(eth_proto), data[14:]

def get_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    v_h_l = data[0]
    v = v_h_l >> 4
    h_l = (v_h_l & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return v, h_l, ttl, proto, ipv4(src), ipv4(target), data[h_l:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    i_t, code, check = struct.unpack('! B B H', data[:4])
    own_id, seq_number = struct.unpack('! H H', data[4:8])
    return i_t, code, check, data[8:]

if __name__ == "__main__":
    main()
