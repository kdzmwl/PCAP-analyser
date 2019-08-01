import dpkt
from scapy.all import *

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET,inet)
    except:
        return False


def sangji(PCAPS):
    nodes=[]
    links=dict()
    from_to=[]
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
            if '源ip'+srcip not in nodes:
                nodes.append('源ip'+srcip)
            if '目的ip'+dstip not in nodes:
                nodes.append('目的ip'+dstip)
            if dport not in nodes:
                nodes.append(dport)
            if ('源ip'+str(srcip)+':'+'目的ip'+str(dstip)+':'+str(dport)) in from_to:
                links['源ip'+str(srcip) + ':' + str(dport)] += lenth
                links[str(dport) + ':' + '目的ip'+str(dstip)] += lenth
            else:
                links['源ip'+str(srcip) + ':' + str(dport)] = lenth
                links[str(dport) + ':' + '目的ip'+str(dstip)] = lenth
        from_to.append('源ip'+str(srcip) + ':' + '目的ip'+str(dstip) + ':' + str(dport))
    return nodes,links

