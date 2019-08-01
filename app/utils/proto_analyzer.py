#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import collections
import dpkt

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        return False

#数据包大小统计
# def pcap_len_statistic(PCAPS):
#     pcap_len_dict = {'0-300':0, '301-600':0, '601-900':0, '901-1200':0, '1201-1500':0}
#     for ts, buf in PCAPS:
#         pcap_len = len(buf)
#         print(pcap_len)
#         print(ts,buf)
#         if 0< pcap_len < 300:
#             pcap_len_dict['0-300'] += 1
#         elif 301 <= pcap_len < 600:
#             pcap_len_dict['301-600'] += 1
#         elif 601 <= pcap_len < 900:
#             pcap_len_dict['601-900'] += 1
#         elif 901 <= pcap_len < 1200:
#             pcap_len_dict['901-1200'] += 1
#         elif 1201 <= pcap_len <= 1500:
#             pcap_len_dict['1201-1500'] += 1
#         else:
#             pass
#     return pcap_len_dict

#常见协议统计IP,IPv6,TCP,UDP,ARP,ICMP,DNS,HTTP,HTTPS,Other
def common_proto_statistic(PCAPS):
    # print(PCAPS)
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['HTTP'] = 0
    common_proto_dict['HTTPS'] = 0
    common_proto_dict['Others'] = 0
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0}
    http_dict = dict()
    dns_dict = dict()
    for ts,buf in PCAPS:
        #
        # print(len(buf))
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            common_proto_dict['IP'] += 1
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                common_proto_dict['TCP'] += 1
                tcp = eth.data.data
                dport = tcp.dport
                sport = tcp.sport
                if dport == 80 or sport == 80:
                    common_proto_dict['HTTP'] += 1
                elif dport == 443 or sport == 443:
                    common_proto_dict['HTTPS'] += 1
                else:
                    common_proto_dict['Others'] += 1
                ip = None
                if dport == 80 or dport == 443:
                    ip = inet_to_str(eth.data.dst)
                elif sport == 80 or sport == 443:
                    ip = inet_to_str(eth.data.src)
                if ip:
                    # print(ip)
                    if ip in http_dict:
                        http_dict[ip] += 1
                    else:
                        http_dict[ip] = 1

            elif isinstance(eth.data.data, dpkt.udp.UDP):
                common_proto_dict['UDP'] += 1
                udp = eth.data.data
                dport = udp.dport
                sport = udp.sport
                if dport == 53 or sport == 53:
                    try:
                        dnss = dpkt.dns.DNS(udp.data)
                        ppap = str(dnss.qd)
                        # print(ppap)
                        moshi = "name='(.*?)',"
                        a = re.findall(moshi, ppap)[0]
                        # print(a)
                        if a in dns_dict:
                            dns_dict[a] += 1
                        else:
                            dns_dict[a] = 1
                        # print(type(dnss.qd))
                    except:
                        None
                    common_proto_dict['DNS'] += 1
                else:
                    common_proto_dict['Others'] += 1
            elif isinstance(eth.data.data, dpkt.icmp.ICMP):
                common_proto_dict['ICMP'] += 1
            elif isinstance(eth.data.data, dpkt.icmp6.ICMP6):
                common_proto_dict['ICMP'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif isinstance(eth.data, dpkt.ip6.IP6):
            common_proto_dict['IPv6'] += 1
        elif eth.type == 2054:
            common_proto_dict['ARP'] += 1
        else:
            common_proto_dict['Others'] += 1

        pcap_len = len(buf)
        if 0 < pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        else:
            pass

    # print(http_dict)
    # print(dns_dict)
    return common_proto_dict,pcap_len_dict, http_dict, dns_dict

#最多协议数量统计
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for ts,buf in PCAPS:
        data = PD.ether_decode(ts,buf)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict

#http/https协议统计
def http_statistic(PCAPS):
    http_dict = dict()
    for ts, buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data.data, dpkt.tcp.TCP):
            tcp = eth.data.data
            dport = tcp.dport
            sport = tcp.sport
            ip = None
            if dport == 80 or dport == 443:
                ip = eth.data.ip
            elif sport == 80 or sport == 443:
                ip = eth.data.ip
            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict

