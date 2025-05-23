# Importando as funções e classes necessárias
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import Counter
import csv
import time

PROTOCOLO_FILTRADO = None

# Contadores de pacotes capturados por protocolo
contador_tcp = 0
contador_udp = 0
contador_outro = 0

# Contadores para IPs de origem e destino
ip_origem_counter = Counter()
ip_destino_counter = Counter()

def classificar_ip(ip):
    if ":" in ip:
        if ip.lower().startswith("fe80"):
            return "Link-local"
        elif ip.lower().startswith("ff"):
            return "Multicast"
        else:
            return "Público"
    else:
        partes = list(map(int, ip.split(".")))
        if partes[0] == 10:
            return "Privado"
        elif partes[0] == 172 and 16 <= partes[1] <= 31:
            return "Privado"
        elif partes[0] == 192 and partes[1] == 168:
            return "Privado"
        elif partes[0] >= 224 and partes[0] <= 239:
            return "Multicast"
        else:
            return "Público"

def analisar_pacote(pacote):
    global contador_tcp, contador_udp, contador_outro
    global ip_origem_counter, ip_destino_counter

    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
    elif IPv6 in pacote:
        ip_origem = pacote[IPv6].src
        ip_destino = pacote[IPv6].dst
    else:
        return
    
    ip_origem_counter[ip_origem] += 1
    ip_destino_counter[ip_destino] += 1

    if TCP in pacote:
        protocolo = "TCP"
        porta_origem = pacote[TCP].sport
        porta_destino = pacote[TCP].dport
        contador_tcp += 1
    elif UDP in pacote:
        protocolo = "UDP"
        porta_origem = pacote[UDP].sport
        porta_destino = pacote[UDP].dport
        contador_udp += 1
    else:
        protocolo = "Outro"
        porta_origem = "N/A"
        porta_destino = "N/A"
        contador_outro += 1

    tipo_origem = classificar_ip(ip_origem)
    tipo_destino = classificar_ip(ip_destino)

    if PROTOCOLO_FILTRADO is None or protocolo == PROTOCOLO_FILTRADO:
        print(f"{ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}")
        print(f"Contadores: TCP: {contador_tcp}, UDP: {contador_udp}, Outro: {contador_outro}\n")

def exibir_top_5():
    print("\n== Top 5 IPs de origem ==")
    for ip, count in ip_origem_counter.most_common(5):
        print(f"{ip}: {count} pacotes")
    
    print("\n== Top 5 IPs de destino ==")
    for ip, count in ip_destino_counter.most_common(5):
        print(f"{ip}: {count} pacotes")

def salvar_em_csv():
    try:
        with open('estatisticas_trafego.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Tipo", "Endereço IP", "Contagem"])

            writer.writerow(["IP de Origem"])
            for ip, count in ip_origem_counter.items():
                writer.writerow([ip, count])

            writer.writerow([])
            writer.writerow(["IP de Destino"])
            for ip, count in ip_destino_counter.items():
                writer.writerow([ip, count])

        print("Arquivo 'estatisticas_trafego.csv' salvo com sucesso.")
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")

# Função principal que captura pacotes em um loop
def capturar_pacotes():
    print("Iniciando a captura de pacotes... (Pressione CTRL+C para parar)\n")
    try:
        while True:
            sniff(prn=analisar_pacote, store=0, timeout=2)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nParando a captura...\n")
        print("Chamando exibir_top_5()")
        exibir_top_5()
        print("Chamando salvar_em_csv()")
        salvar_em_csv()
        print("Análise completa! Obrigado por usar o analisador de tráfego.", flush=True)

# Start capturing
capturar_pacotes()
