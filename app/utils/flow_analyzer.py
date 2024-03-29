#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import collections
import time
import dpkt

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET,inet)
    except:
        return False

#时间流量图
def time_flow(PCAPS):
    time_list=[]
    len_list=[]

    time_flow_dict = collections.OrderedDict()
    time_flow_dict2 = collections.OrderedDict()
    for ts, buf in PCAPS:
        time_list.append(ts)
        len_list.append(len(buf))
    start = time_list[0]
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start))] = len_list[0]
    time_flow_dict[start] = len_list[0]
    for i in range(len(time_list)):
        timediff2 = time_list[i] - start
        timediff = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time_list[i]))
        if timediff in time_flow_dict.keys():
            time_flow_dict[timediff] = len_list[i] + time_flow_dict[timediff]
        else:
            time_flow_dict[timediff] = len_list[i]
        time_flow_dict2[timediff2] = len_list[i]
    return time_flow_dict,time_flow_dict2



#获取抓包主机的IP
def get_host_ip(PCAPS):
    ip_list = list()
    for ts,buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip_list.append(inet_to_str(eth.data.src))
            ip_list.append(inet_to_str(eth.data.dst))
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip

#数据流入流出统计
def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for ts,buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            if inet_to_str(eth.data.src) == host_ip:
                data_flow_dict['OUT'] += 1
            elif inet_to_str(eth.data.dst) == host_ip:
                data_flow_dict['IN'] += 1
            else:
                pass
    return data_flow_dict

#访问IP地址统计
def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for ts, buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            dst = inet_to_str(eth.data.dst)
            src = inet_to_str(eth.data.src)
            pcap_len = len(buf)
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d:d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(), key=lambda d:d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d:d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(), key=lambda d:d[1], reverse=False)
    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)
    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)
    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)
    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)
    in_ip_dict = {'in_keyp': in_keyp_list, 'in_packet': in_packet_list, 'in_keyl': in_keyl_list, 'in_len': in_len_list, 'out_keyp': out_keyp_list, 'out_packet': out_packet_list, 'out_keyl': out_keyl_list, 'out_len': out_len_list}
    return in_ip_dict

#常见协议流量统计
def proto_flow(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for ts,buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        pcap_len = len(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            proto_flow_dict['IP'] += pcap_len
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                proto_flow_dict['TCP'] += pcap_len
                tcp = eth.data.data
                dport = tcp.dport
                sport = tcp.sport
                if dport == 80 or sport == 80:
                    proto_flow_dict['HTTP'] += pcap_len
                elif dport == 443 or sport == 443:
                    proto_flow_dict['HTTPS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            elif isinstance(eth.data.data, dpkt.udp.UDP):
                proto_flow_dict['UDP'] += pcap_len
                udp = eth.data.data
                dport = udp.dport
                sport = udp.sport
                if dport == 53 or sport == 53:
                    proto_flow_dict['DNS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            elif isinstance(eth.data.data, dpkt.icmp.ICMP):
                proto_flow_dict['ICMP'] += pcap_len
            elif isinstance(eth.data.data, dpkt.icmp6.ICMP6):
                proto_flow_dict['ICMP'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif isinstance(eth.data, dpkt.ip6.IP6):
            proto_flow_dict['IPv6'] += pcap_len
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                proto_flow_dict['TCP'] += pcap_len
                tcp = eth.data.data
                dport = tcp.dport
                sport = tcp.sport
                if dport == 80 or sport == 80:
                    proto_flow_dict['HTTP'] += pcap_len
                elif dport == 443 or sport == 443:
                    proto_flow_dict['HTTPS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            elif isinstance(eth.data.data, dpkt.udp.UDP):
                proto_flow_dict['UDP'] += pcap_len
                udp = eth.data.data
                dport = udp.dport
                sport = udp.sport
                if dport == 53 or sport == 53:
                    proto_flow_dict['DNS'] += pcap_len
                else:
                    proto_flow_dict['Others'] += pcap_len
            elif isinstance(eth.data.data, dpkt.icmp.ICMP):
                proto_flow_dict['ICMP'] += pcap_len
            elif isinstance(eth.data.data, dpkt.icmp6.ICMP6):
                proto_flow_dict['ICMP'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif eth.type==2054:
            proto_flow_dict['ARP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict

#流量最多协议数量统计
def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for ts,buf in PCAPS:
        data = PD.ether_decode(ts,buf)
        most_flow_dict[data['Procotol']] += len(buf)
    return most_flow_dict