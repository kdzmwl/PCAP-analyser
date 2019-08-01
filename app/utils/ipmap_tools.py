#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import os
import geoip2.database
import dpkt
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except:
        return False

#获取经纬度
def get_geo(ip):
    reader = geoip2.database.Reader(os.getcwd()+'/app/utils/GeoIP/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
        city_name = response.country.names['zh-CN']+response.city.names['zh-CN']
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except:
        return None

#IP地图数据
def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_value_list = list()
    from_to_dict=dict()
    for ts,buf in PCAPS:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            src =  inet_to_str(eth.data.src)
            dst =  inet_to_str(eth.data.dst)
            pcap_len = len(buf)
            # if src == host_ip:
            #     oip = dst
            # else:
            #     oip = src
            # if oip in ip_value_dict:
            #     ip_value_dict[oip] += pcap_len
            # else:
            #     ip_value_dict[oip] = pcap_len
            if (src,dst) in from_to_dict.keys():
                from_to_dict[(src,dst)] += pcap_len
            else:
                from_to_dict[(src,dst)] = pcap_len
    # for ip, value in ip_value_dict.items():
    #     geo_list = get_geo(ip)
    #     if geo_list:
    #         geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
    #         Mvalue = str(float('%.2f'%(value/1024.0)))+':'+ip
    #         ip_value_list.append({geo_list[0]:Mvalue})
    #     else:
    #         pass
    for ip ,value in from_to_dict.items():
        geo_list = get_geo(ip[0])
        geo_list2 =get_geo(ip[1])
        if geo_list and geo_list2:
            geo_dict[str(geo_list[0])+":"+str(geo_list2[0])] = [[geo_list[1], geo_list[2]],[geo_list2[1],geo_list2[2]]]
            Mvalue = str(float('%.2f' % (value / 1024.0))) + ':' + ip[0] + ':'+ ip[1]
            ip_value_list.append({str(geo_list[0])+":"+str(geo_list2[0]): Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]