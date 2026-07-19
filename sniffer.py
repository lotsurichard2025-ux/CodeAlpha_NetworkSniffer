from scapy.all import sniff, IP, TCP, UDP, Raw

PROTOCOLES = {1: "ICMP", 6: "TCP", 17: "UDP"}

def afficher_paquet(paquet):
    if paquet.haslayer(IP):
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
        proto_num = paquet[IP].proto
        proto_nom = PROTOCOLES.get(proto_num, f"Autre({proto_num})")

        ligne = f"[{proto_nom}] {ip_src} -> {ip_dst}"

        if paquet.haslayer(TCP):
            ligne += f" | Port: {paquet[TCP].sport} -> {paquet[TCP].dport}"
        elif paquet.haslayer(UDP):
            ligne += f" | Port: {paquet[UDP].sport} -> {paquet[UDP].dport}"

        if paquet.haslayer(Raw):
            payload = bytes(paquet[Raw].load)
            ligne += f" | Payload: {payload[:20]}"

        print(ligne)

sniff(filter="icmp", prn=afficher_paquet, count=10)