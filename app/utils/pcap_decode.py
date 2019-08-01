#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import time
import dpkt

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET,inet)
    except:
        return False

class PcapDecode:
    def __init__(self):
        #ETHER:读取以太网层协议配置文件
        with open('./app/utils/protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        #IP:读取IP层协议配置文件
        with open('./app/utils/protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        #PORT:读取应用层协议端口配置文件
        with open('./app/utils/protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        #TCP:读取TCP层协议配置文件
        with open('./app/utils/protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        #UDP:读取UDP层协议配置文件
        with open('./app/utils/protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    #解析以太网层协议
    def ether_decode(self, t,p):
        data = dict()
        if dpkt.ethernet.Ethernet(p)!=b'':
            eth = dpkt.ethernet.Ethernet(p)
            if eth.type==2048:
                data = self.ip_decode(t,p)
            elif eth.type==2054:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
                data['Source'] = 'Unknow'
                data['Destination'] = 'Unknow'
                data['Procotol'] = 'ARP'
                data['len'] = len(p)
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
                data['Source'] = 'Unknow'
                data['Destination'] = 'Unknow'
                data['Procotol'] = 'Unknow'
                data['len'] = len(p)
            return data
        else:
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
            data['Source'] = 'Unknow'
            data['Destination'] = 'Unknow'
            data['Procotol'] = 'Unknow'
            data['len'] = len(p)
            return data

    #解析IP层协议
    def ip_decode(self, t,p):
        data = dict()
        eth = dpkt.ethernet.Ethernet(p)
        if isinstance(eth.data, dpkt.ip.IP):  #2048:Internet IP (IPv4)
            ip = eth.data
            if isinstance(eth.data.data, dpkt.tcp.TCP):  #6:TCP
                data = self.tcp_decode(t,p, ip)
                return data
            elif isinstance(eth.data.data, dpkt.udp.UDP): #17:UDP
                data = self.udp_decode(t,p, ip)
                return data
            elif isinstance(eth.data.data, dpkt.icmp.ICMP):
                data = self.icmp_decode(t,p, ip)
                return data
            elif isinstance(eth.data.data, dpkt.icmp6.ICMP6):
                data = self.icmp6_decode(t,p, ip)
                return data
            else:
                ip = eth.data
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
                data['Source'] = inet_to_str(ip.src)
                data['Destination'] = inet_to_str(ip.dst)
                data['Procotol'] = 'IP'
                data['len'] = len(p)
                return data
        elif isinstance(eth.data, dpkt.ip6.IP6):  #34525:IPv6
            ipv6 = eth.data
            if isinstance(eth.data.data, dpkt.tcp.TCP):  #6:TCP
                data = self.tcp_decode(t,p, ipv6)
                return data
            elif isinstance(eth.data.data, dpkt.udp.UDP): #17:UDP
                data = self.udp_decode(t,p, ipv6)
                return data
            elif isinstance(eth.data.data, dpkt.icmp.ICMP):
                data = self.icmp_decode(t,p, ipv6)
                return data
            elif isinstance(eth.data.data, dpkt.icmp6.ICMP6):
                data = self.icmp_decode(t,p, ipv6)
                return data
            else:
                ip = eth.data
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
                data['Source'] = inet_to_str(ip.src)
                data['Destination'] = inet_to_str(ip.dst)
                data['Procotol'] = 'IP'
                data['len'] = len(p)
                return data
        else:
            ip = eth.data
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
            data['Source'] = inet_to_str(ip.src)
            data['Destination'] = inet_to_str(ip.dst)
            data['Procotol'] = 'Unknow'
            data['len'] = len(p)
            return data

    #解析TCP层协议
    def tcp_decode(self, t,p, ip):
        data = dict()
        tcp = ip.data
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
        data['Source'] = inet_to_str(ip.src) + ":" + str(tcp.sport)
        data['Destination'] = inet_to_str(ip.dst) + ":" + str(tcp.dport)
        data['len'] = len(p)
        if tcp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Procotol'] = "TCP"
        return data

    #解析UDP层协议
    def udp_decode(self, t,p, ip):
        data = dict()
        udp = ip.data
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
        data['Source'] = inet_to_str(ip.src) + ":" + str(udp.sport)
        data['Destination'] = inet_to_str(ip.dst) + ":" + str(udp.dport)
        data['len'] = len(p)
        if udp.dport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.sport]
        else:
            data['Procotol'] = "UDP"
        return data

    def icmp_decode(self, t,p, ip):
        data = dict()
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
        data['Source'] = inet_to_str(ip.src)
        data['Destination'] = inet_to_str(ip.dst)
        data['len'] = len(p)
        data['Procotol'] = "ICMP"
        return data