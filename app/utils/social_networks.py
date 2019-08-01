import dpkt
from scapy.all import *

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET,inet)
    except:
        return False

def social(PCAPS):
    nodes=dict()
    links=dict()
    dport=None
    srcip=None
    dstip=None
    for ts,buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip=eth.data
            srcip=inet_to_str(ip.src)
            dstip=inet_to_str(ip.dst)
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                tcp=ip.data
                dport=tcp.dport
                lenth=len(buf)
            elif isinstance(eth.data.data, dpkt.udp.UDP):
                udp = ip.data
                dport = udp.dport
                lenth = len(buf)
        if srcip and dstip and dport:
            if srcip not in list(nodes.keys()):
                nodes[srcip]=1
            else:
                nodes[srcip] += 1
            if dstip not in list(nodes.keys()):
                nodes[dstip] = 1
            else:
                nodes[dstip] += 1
            if (str(srcip)+':'+str(dstip)) in list(links.keys()):
                links[str(srcip) + ':' + str(dstip)] += float('%.2f' % (lenth / 1024.0))
            else:
                links[str(srcip) + ':' + str(dstip)] = float('%.2f' % (lenth / 1024.0))
    return nodes,links