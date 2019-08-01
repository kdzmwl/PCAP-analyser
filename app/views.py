#coding:UTF-8
__author__ = 'dj'

from app import app
from flask import render_template, request, flash, redirect, url_for
from .forms import Upload
from .utils.upload_tools import allowed_file
from .utils.pcap_decode import PcapDecode
from .utils.trafficdistribution import sangji
from .utils.social_networks import social
from .utils.proto_analyzer import common_proto_statistic, most_proto_statistic
from .utils.flow_analyzer import time_flow, data_flow, get_host_ip, data_in_out_ip, proto_flow, most_flow_statistic
from .utils.ipmap_tools import get_ipmap, get_geo
import dpkt
import os
import json
#导入函数到模板中
app.jinja_env.globals['enumerate'] = enumerate
PCAPS = None
#全局变量
PCAP_NAME = ''     #上传文件名
PD = PcapDecode()  #解析器
raw_pcapfile = './pcaps'
#--------------------------------------------------------首页，上传---------------------------------------------
#首页
@app.route('/', methods=['POST', 'GET'])
@app.route('/index/', methods=['POST', 'GET'])
def index():
    return render_template('./home/index.html')


#数据包上传
@app.route('/upload/', methods=['POST', 'GET'])
def upload():
    upload = Upload()
    if request.method == 'GET':
        return render_template('./upload/upload.html')
    elif request.method == 'POST':
        pcap = upload.pcap.data
        if upload.validate_on_submit():
            pcapname = pcap.filename

            if allowed_file(pcapname):
                global PCAPS
                global PCAP_NAME
                PCAP_NAME = pcapname
                PCAP_NAME = PCAP_NAME[:-5]
                print(raw_pcapfile + '/' + pcapname)
                try:
                    f = open(raw_pcapfile+'/'+pcapname, 'rb')

                    PCAPS = dpkt.pcap.Reader(f)
                    PCAPS = list(PCAPS)
                    f.close()
                    flash('恭喜你,上传成功！')
                    try:
                        os.mkdir('./info/'+PCAP_NAME)
                    except:
                        None
                    return render_template('./upload/upload.html')
                except Exception as e:
                    flash('上传错误,错误信息:' + e.message)
                    # print('EEEEEEEEEEEEEEEEEEEEEEEEEEEEE')
                    return render_template('./upload/upload.html')
            else:
                flash('上传失败,请上传允许的数据包格式!')
                return render_template('./upload/upload.html')
        else:
            return render_template('./upload/upload.html')
    return render_template('./upload/upload.html')


#-------------------------------------------数据分析----------------------------------------------------
#协议分析
@app.route('/protoanalyzer/', methods=['POST', 'GET'])
def protoanalyzer():
    # print(destination)
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('upload'))
    else:

        if os.path.exists('./info/' + PCAP_NAME + '/protoanalyzer/data_dict.json'):
            # print('./info/' + PCAP_NAME + '/data_dict.json')
            with open('./info/' + PCAP_NAME + '/protoanalyzer/data_dict.json', 'r', encoding='utf-8')as f:
                data_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/pcap_len_dict.json', 'r', encoding='utf-8')as f:
                pcap_len_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/http_dict.json', 'r', encoding='utf-8')as f:
                http_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/dns_dict.json', 'r', encoding='utf-8')as f:
                dns_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/pcap_count_dict.json', 'r', encoding='utf-8')as f:
                pcap_count_dict = json.load(f)
        else:
            data_dict, pcap_len_dict, http_dict, dns_dict = common_proto_statistic(PCAPS)
            pcap_count_dict = most_proto_statistic(PCAPS, PD)
            try:
                os.mkdir('./info/' + PCAP_NAME + '/protoanalyzer/')
            except:
                pass
            with open('./info/' + PCAP_NAME + '/protoanalyzer/data_dict.json', 'w', encoding='utf-8')as f:
                json.dump(data_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/pcap_len_dict.json', 'w', encoding='utf-8')as f:
                json.dump(pcap_len_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/http_dict.json', 'w', encoding='utf-8')as f:
                json.dump(http_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/dns_dict.json', 'w', encoding='utf-8')as f:
                json.dump(dns_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/protoanalyzer/pcap_count_dict.json', 'w', encoding='utf-8')as f:
                json.dump(pcap_count_dict, f, indent=4, ensure_ascii=False)

        http_dict = sorted(http_dict.items(), key=lambda d:d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)

        dns_dict = sorted(dns_dict.items(), key=lambda d:d[1], reverse=False)
        dns_key_list = list()
        dns_value_list = list()
        for key, value in dns_dict:
            dns_key_list.append(key)
            dns_value_list.append(value)
        return render_template('./dataanalyzer/protoanalyzer.html', data=list(data_dict.values()), pcap_len=pcap_len_dict, pcap_keys=list(pcap_count_dict.keys()), http_key=http_key_list, http_value=http_value_list, dns_key=dns_key_list, dns_value=dns_value_list, pcap_count=pcap_count_dict)

# def protoanalyzer():
#     print(destination)
#     if PCAPS == None:
#         flash("请先上传要分析的数据包!")
#         return redirect(url_for('upload'))
#     else:
#         data_dict = common_proto_statistic(PCAPS)
#         pcap_len_dict = pcap_len_statistic(PCAPS)
#         pcap_count_dict = most_proto_statistic(PCAPS, PD)
#         http_dict = http_statistic(PCAPS)
#         http_dict = sorted(http_dict.items(), key=lambda d:d[1], reverse=False)
#         http_key_list = list()
#         http_value_list = list()
#         for key, value in http_dict:
#             http_key_list.append(key)
#             http_value_list.append(value)
#         dns_dict = dns_statistic(PCAPS)
#         dns_dict = sorted(dns_dict.items(), key=lambda d:d[1], reverse=False)
#         dns_key_list = list()
#         dns_value_list = list()
#         for key, value in dns_dict:
#             dns_key_list.append(key.decode('utf-8'))
#             dns_value_list.append(value)
#         return render_template('./dataanalyzer/protoanalyzer.html', data=list(data_dict.values()), pcap_len=pcap_len_dict, pcap_keys=list(pcap_count_dict.keys()), http_key=http_key_list, http_value=http_value_list, dns_key=dns_key_list, dns_value=dns_value_list, pcap_count=pcap_count_dict)



#流量分析
@app.route('/flowanalyzer/', methods=['POST', 'GET'])
def flowanalyzer():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('upload'))
    else:

        if os.path.exists('./info/' + PCAP_NAME + '/flowanalyzer/time_flow_dict.json'):
            # print('./info/' + PCAP_NAME + '/data_dict.json')
            with open('./info/' + PCAP_NAME + '/flowanalyzer/time_flow_dict.json', 'r', encoding='utf-8')as f:
                time_flow_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/time_flow_dict2.json', 'r', encoding='utf-8')as f:
                time_flow_dict2 = json.load(f)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/data_flow_dict.json', 'r', encoding='utf-8')as f:
                data_flow_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/data_ip_dict.json', 'r', encoding='utf-8')as f:
                data_ip_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/proto_flow_dict.json', 'r', encoding='utf-8')as f:
                proto_flow_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/most_flow_dict.json', 'r', encoding='utf-8')as f:
                most_flow_dict = json.load(f)

        else:

            time_flow_dict, time_flow_dict2 = time_flow(PCAPS)
            host_ip = get_host_ip(PCAPS)
            data_flow_dict = data_flow(PCAPS, host_ip)
            data_ip_dict = data_in_out_ip(PCAPS, host_ip)
            proto_flow_dict = proto_flow(PCAPS)
            most_flow_dict = most_flow_statistic(PCAPS, PD)
            most_flow_dict = sorted(most_flow_dict.items(), key=lambda d: d[1], reverse=True)
            try:
                os.mkdir('./info/' + PCAP_NAME + '/flowanalyzer/')
            except:
                pass

            with open('./info/' + PCAP_NAME + '/flowanalyzer/time_flow_dict.json', 'w', encoding='utf-8')as f:
                json.dump(time_flow_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/time_flow_dict2.json', 'w', encoding='utf-8')as f:
                json.dump(time_flow_dict2, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/data_flow_dict.json', 'w', encoding='utf-8')as f:
                json.dump(data_flow_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/data_ip_dict.json', 'w', encoding='utf-8')as f:
                json.dump(data_ip_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/proto_flow_dict.json', 'w', encoding='utf-8')as f:
                json.dump(proto_flow_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/flowanalyzer/most_flow_dict.json', 'w', encoding='utf-8')as f:
                json.dump(most_flow_dict, f, indent=4, ensure_ascii=False)


        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        return render_template('./dataanalyzer/flowanalyzer.html', time_flow_keys=list(time_flow_dict.keys()), time_flow_values=list(time_flow_dict.values()),time_flow_keys2=list(time_flow_dict2.keys()), time_flow_values2=list(time_flow_dict2.values()), data_flow=data_flow_dict, ip_flow=data_ip_dict, proto_flow=list(proto_flow_dict.values()), most_flow_key=most_flow_key, most_flow_dict=most_flow_dict)

#访问地图
@app.route('/ipmap/', methods=['POST', 'GET'])
def ipmap():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('upload'))
    else:
        if os.path.exists('./info/' + PCAP_NAME + '/map_info/geo_dict.json'):
            # print('./info/' + PCAP_NAME + '/data_dict.json')
            with open('./info/' + PCAP_NAME + '/map_info/geo_dict.json', 'r', encoding='utf-8')as f:
                geo_dict = json.load(f)
            with open('./info/' + PCAP_NAME + '/map_info/ip_value_list.json', 'r', encoding='utf-8')as f:
                ip_value_list = json.load(f)
            with open('./info/' + PCAP_NAME + '/map_info/host_ip.json', 'r', encoding='utf-8')as f:
                host_ip = json.load(f)

        else:

        #myip = getmyip()
        # myip = '223.166.118.164'
        # myip = get_host_ip(PCAPS)
        # if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)
            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            try:
                os.mkdir('./info/' + PCAP_NAME + '/map_info/')
            except:
                pass
            with open('./info/' + PCAP_NAME + '/map_info/geo_dict.json', 'w', encoding='utf-8')as f:
                json.dump(geo_dict, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/map_info/ip_value_list.json', 'w', encoding='utf-8')as f:
                json.dump(ip_value_list, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/map_info/host_ip.json', 'w', encoding='utf-8')as f:
                json.dump(host_ip, f, indent=4, ensure_ascii=False)
        myip_geo = get_geo(host_ip)
        ip_value_list = [(list(d.keys())[0], list(d.values())[0]) for d in ip_value_list]
        # print(ip_value_list)
        # print(geo_dict)
        print(ip_value_list)
        print(myip_geo)
        return render_template('./dataanalyzer/ipmap.html', geo_data=geo_dict, ip_value=ip_value_list, mygeo=myip_geo)
        # else:
        #     return render_template('./error/neterror.html')

@app.route('/trafficdistribution/', methods=['POST', 'GET'])
def trafficdistribution():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('upload'))
    else:
        # node_dict = []
        # links_dict = []
        if os.path.exists('./info/'+PCAP_NAME+'/trafficdistribution/nodes.json'):
            with open('./info/'+PCAP_NAME+'/trafficdistribution/nodes.json', 'r', encoding='utf-8')as f:
                nodes=json.load(f)
            with open('./info/'+PCAP_NAME+'/trafficdistribution/links.json', 'r', encoding='utf-8')as f:
                links=json.load(f)
        else:
            nodes,links=sangji(PCAPS)
            try:
                os.mkdir('./info/' + PCAP_NAME + '/trafficdistribution/')
            except:
                pass
            with open('./info/' + PCAP_NAME + '/trafficdistribution/nodes.json', 'w', encoding='utf-8')as f:
                json.dump(nodes, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/trafficdistribution/links.json', 'w', encoding='utf-8')as f:
                json.dump(links, f, indent=4, ensure_ascii=False)

        nodes2=[]
        links2={}
        links = dict(sorted(links.items(), key=lambda p: p[1],reverse=True))
        for i,keys in zip(range(len(links)),links.keys()):
            links2[keys]=links[keys]
        num=links2[list(links2.keys())[0]]
        for i in list(links.keys()):
            if links[i]<num*0.02:
                del links[i]
        for i in links:
            if i.split(':')[0] not in nodes2:
                nodes2.append(i.split(':')[0])
            if i.split(':')[1] not in nodes2:
                nodes2.append(i.split(':')[1])

        # for i in nodes:
        #     node_dict.append({'name':i})
        # for i in links:
        #     links_dict.append({'source':i.split(':')[0],'target':i.split(':')[1],'value':links[i]})
        # with open('./info/' + PCAP_NAME + '/node_dict.json', 'w', encoding='utf-8')as f:
        #     json.dump(node_dict, f, indent=4, ensure_ascii=False)
        # with open('./info/' + PCAP_NAME + '/links_dict.json', 'w', encoding='utf-8')as f:
        #     json.dump(links_dict, f, indent=4, ensure_ascii=False)
        # print(nodes)
        # print(links)
    return render_template('./trafficdistribution/sangji.html',nodes=nodes2,links=links)

@app.route('/social_networks/', methods=['POST', 'GET'])
def social_networks():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('upload'))
    else:
        if os.path.exists('./info/' + PCAP_NAME + '/social_networks/ip_nodes.json'):
            with open('./info/' + PCAP_NAME + '/social_networks/ip_nodes.json', 'r', encoding='utf-8')as f:
                nodes = json.load(f)
            with open('./info/' + PCAP_NAME + '/social_networks/ip_links.json', 'r', encoding='utf-8')as f:
                links = json.load(f)
        else:
            nodes,links=social(PCAPS)
            try:
                os.mkdir('./info/' + PCAP_NAME + '/social_networks/')
            except:
                pass
            with open('./info/' + PCAP_NAME + '/social_networks/ip_nodes.json', 'w', encoding='utf-8')as f:
                json.dump(nodes, f, indent=4, ensure_ascii=False)
            with open('./info/' + PCAP_NAME + '/social_networks/ip_links.json', 'w', encoding='utf-8')as f:
                json.dump(links, f, indent=4, ensure_ascii=False)
        for each in nodes.keys():
            if nodes[each]<100:
                nodes[each]=1000

        return render_template('./socialnetworks/social_networks.html', nodes=nodes, links=links)

# ----------------------------------------------错误处理页面---------------------------------------------
@app.errorhandler(404)
def internal_error(error):
    return render_template('./error/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('./error/500.html'), 500