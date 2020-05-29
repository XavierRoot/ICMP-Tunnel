#!/usr/bin/env python
# -*- encoding=utf-8 -*-

import time
import struct
from socket import socket,AF_INET,SOCK_RAW,IPPROTO_ICMP



# ping 结构
_type=8 # ICMP type 8,0
code=0 # ICMP code,0,0
checksum=1 # 校验和
identifier=1 # 标识符
sequence=17 # 报文序号
data='' # 数据

sending_ts = time.time()
data = b'hello icmp,Let\'s start Hacking'
#payload = struct.pack('!d',sending_ts)

payload = struct.pack('!d'+str(len(data)+1)+'p',sending_ts,data)

# ! 表示 网络 字节序 ， d 表示双精度浮点。
#  B 表示长度为一个字节的无符号整数， H 表示长度为两个字节的无符号整数。
header = struct.pack('!BBHHH',_type,code,checksum,identifier,sequence)
icmp = header + payload

print("payload= ",payload)
print(icmp)

def calculae_checksum(icmp):
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
    print("checksum =",checksum)

    return struct.pack('!H',checksum)

checksum = calculae_checksum(icmp)
print("checksum = ",checksum)

icmp = header[:2] + checksum + header[4:] + payload

print("icmp2=",icmp)

s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
addr='192.168.66.132'
# 调用 sendto 系统调用发送 ICMP 报文：参数1为封装好的ICMP报文； 参数2为发送标志位，一般填0；参数3为目的IP-端口，端口这里填 0
s.sendto(icmp,0,(addr,0))

ip,(src_ip,_) = s.recvfrom(1500)
#参数为接收缓冲区大小，这里用 1500 刚好是一个典型的 MTU 大小。 注意到， recvfrom 系统调用返回 IP 报文，去掉前 20 字节的 IP 头部便得到 ICMP 报文。
print("ip:",ip)
print('src_ip:',src_ip)
print('_:',_)
print('icmp:',ip[20:])
