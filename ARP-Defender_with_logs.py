import scapy.all as scapy
import time 
g='\033[92m'
r='\033[91m'
res='\033[0m'
c='\033[36m'
y="\033[93m"
d="\033[1;41m\033[37m"
b='\033[1;96m'

last=0
stop=False
def check_stop(p):
    return stop
banner=r""""                                 
 ____      ___           _         
|    \ ___|  _|___ ___ _| |___ ___ 
|  |  | -_|  _| -_|   | . | -_|  _|
|____/|___|_| |___|_|_|___|___|_|  
                               
"""
print(f'{b}{banner}{res}')
real={}
def mac_rout(ip):
    broad=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp=scapy.ARP(pdst=ip)
    packet=broad/arp
    ans,unans=scapy.srp(packet,verbose=0,timeout=1)
    if ans:
       return ans[0][1].hwsrc
    return None


try:            
    ip_a=input(f"{c}[*]{res} Введите IP роутера:")

    real[ip_a]=mac_rout(ip_a)
    if real[ip_a]==None:
        print(f"{r}[-]{res} Роутер не отвечает")
        exit()
except KeyboardInterrupt:
    print(f"\n{y}[!]{res} Остановлено")
    exit()
def restore(ip_t,ip_r,mac_t,mac_r):
    rest_pkt=scapy.ARP(op=2,pdst=ip_t,psrc=ip_r,hwdst=mac_t,hwsrc=mac_r)
    for i in range(5):
        scapy.send(rest_pkt,verbose=0,count=10)
        time.sleep(0.1)
    

def detect(pkt):
    global last
    if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op==2:
        sender=pkt[scapy.ARP].psrc#айпи злоум
        mac=pkt[scapy.ARP].hwsrc#мак злоум
        victim=pkt[scapy.ARP].hwdst#мак жертвы
        victim_ip=pkt[scapy.ARP].pdst#айпи жертвы
        if sender in real:
            real_mac=real[sender]
            if real_mac!=mac:
                time_result=time.strftime("%H:%M:%S")
                cur=time.time()
                if cur - last >10:
                    log=f"ARP: {mac} проводит арп спуфинг на устройстово {victim_ip} c mac:{victim}, время:{time_result}"
                    with open("logs.txt","a") as f:
                        f.write(f"{log} \n")
                    last=cur
                print(f"{d}[!!!]{res} Устройство с {mac} притворяется роутером и обманывает {victim_ip} с mac {victim}. Настоящий мак {real_mac}")
                restore(victim_ip,ip_a,victim,real_mac)
                restore(ip_a,victim_ip,real_mac,victim)
           
                
                
try:
    print(f"{g}[+]{res} Данные заполнены: {real} ")
    print(f"{g}[+]{res} Мониторинг активирован. Слушаю сеть...")
    scapy.sniff(filter="arp",store=0,prn=detect,stop_filter=check_stop)
except KeyboardInterrupt:
    stop=True
    print(f"\n{y}[!]{res} Мониторинг остановлен")
except PermissionError:
    print(f"\n{y}[!]{res} Запустите скрипт через sudo!")
except Exception as e:
    print(f"\n{y}[!]{res} Произошла ошибка {e}")
