# Importando as funções e classes necessárias do Scapy
from scapy.all import sniff, IP, IPv6, TCP, UDP


# Protocolo a ser filtrado: "TCP", "UDP" ou "Outro" (deixe como None para capturar tudo)
PROTOCOLO_FILTRADO = None

# Contadores de pacotes capturados por protocolo
contador_tcp = 0
contador_udp = 0
contador_outro = 0

# Lista para armazenar os dados dos pacotes capturados
pacotes_salvos = []


# Função para classificar o tipo de endereço IP (público, privado, Link-Local ou Multicast)
def classificar_ip(ip):
    #Verifica se o IP contém ":" (indicando que é um IPv6)
    if ":" in ip:
        # É um endereço IPv6
        if ip.lower().startswith("fe80"):
            return "Link-local" # IP local usado para comunicação entre dispositivos na mesma rede
        elif ip.lower().startswith("ff"):
            return "Multicast" # IP usado para comunicação entre grupos
        else:
            return "Público" # Qualquer outro IP IPv6 é considerado público
    else:
        # IP é do tipo IPv4 -> divide pelos pontos e transforma em números inteiros
        partes = list(map(int, ip.split(".")))
        if partes[0] == 10:
            return "Privado" # Faixa privada 10.0.0.0/8
        elif partes[0] == 172 and 16 <= partes[1] <= 31:
            return "Privado" # Faixa privada 172.16.0.0/12
        elif partes[0] == 192 and partes[1] == 168:
            return "Privado" # Faixa privada 192.168.0.0/16
        elif partes[0] >= 224 and partes[0] <= 239:
            return "Multicast" # Faixa 224.0.0.0 a 239.255.255.255
        else:
            return "Público"  # Fora das faixas privadas, é público


# Função chamada para cada pacote capturado
def analisar_pacote(pacote):
    global contador_tcp, contador_udp, contador_outro

    # Verifica se o pacote é do tipo IPv4
    if IP in pacote:
          ip_origem = pacote[IP].src  # Endereço de origem (quem enviou)
          ip_destino = pacote[IP].dst  # Endereço de destino (quem deve receber)

          # Verifica se o pacote contém protocolo TCP ou UDP
          if TCP in pacote:
              protocolo = "TCP"  # Protocolo TCP
              porta_origem = pacote[TCP].sport
              porta_destino = pacote[TCP].dport
          elif UDP in pacote:
              protocolo = "UDP"  # Protocolo UDP
              porta_origem = pacote[UDP].sport
              porta_destino = pacote[UDP].dport
          else:
              protocolo = "Outro"
              porta_origem = "N/A"
              porta_destino = "N/A"

          tipo_origem = classificar_ip(ip_origem)  # Classifica o IP de origem
          tipo_destino = classificar_ip(ip_destino)  # Classifica o IP de destino

          # Exibe o resultado formatado
          #print(f"[IPv4] {ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}") 
          
          # Aplica o filtro de protocolo
          if PROTOCOLO_FILTRADO is None or protocolo == PROTOCOLO_FILTRADO:
              # Atualiza os contadores de pacotes
              if protocolo == "TCP":
                  contador_tcp += 1
              elif protocolo == "UDP":
                  contador_udp += 1
              else:
                  contador_outro += 1
              print(f"[IPv4] {ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}")
              print(f"Contadores: TCP: {contador_tcp}, UDP: {contador_udp}, Outro: {contador_outro}\n")

              pacotes_salvos.append({
                  "versao_ip": 4,
                  "ip_origem": ip_origem,
                  "porta_origem": porta_origem,
                  "tipo_origem": tipo_origem,
                  "ip_destino": ip_destino,
                  "porta_destino": porta_destino,
                  "tipo_destino": tipo_destino,
                  "protocolo": protocolo,
              })  # Adiciona o pacote à lista de pacotes salvos


    # Verifica se o pacote é do tipo IPv6
    elif IPv6 in pacote:
          ip_origem = pacote[IPv6].src  # IP de origem
          ip_destino = pacote[IPv6].dst # IP de destino

          if TCP in pacote:
              protocolo = "TCP"
              porta_origem = pacote[TCP].sport
              porta_destino = pacote[TCP].dport
          elif UDP in pacote:
              protocolo = "UDP"
              porta_origem = pacote[UDP].sport
              porta_destino = pacote[UDP].dport
          else:
              protocolo = "Outro"
              porta_origem = "N/A"
              porta_destino = "N/A"
          
          tipo_origem = classificar_ip(ip_origem)  # Classifica o IP de origem
          tipo_destino = classificar_ip(ip_destino)  # Classifica o IP de destino

          # Exibe as informações do pacote IPv6
          #print(f"[IPv6] {ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}")
          
          # Aplica o filtro de protocolo
          if PROTOCOLO_FILTRADO is None or protocolo == PROTOCOLO_FILTRADO:
            # Atualiza os contadores de pacotes
            if protocolo == "TCP":
                contador_tcp += 1
            elif protocolo == "UDP":
                contador_udp += 1
            else:
                contador_outro += 1
            print(f"[IPv6] {ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}")
            print(f"Contadores: TCP: {contador_tcp}, UDP: {contador_udp}, Outro: {contador_outro}\n")

            pacotes_salvos.append({
                "versao_ip": 6,
                "ip_origem": ip_origem,
                "porta_origem": porta_origem,
                "tipo_origem": tipo_origem,
                "ip_destino": ip_destino,
                "porta_destino": porta_destino,
                "tipo_destino": tipo_destino,
                "protocolo": protocolo,
            }) # Adiciona o pacote à lista de pacotes salvos

try:
    sniff(prn=analisar_pacote, store=0, timeout=5)
except KeyboardInterrupt:
    print("\nCaptura interrompida pelo usuário.")
    print(f"Total de pacotes capturados: {contador_tcp + contador_udp + contador_outro}")

    # Salva os pacotes no arquivo JSON
    import json
    with open("pacotes_capturados.json", "w", encoding="utf-8") as f:
        json.dump(pacotes_salvos, f, ensure_ascii=False, indent=4)

    print("Pacotes salvos em pacotes_capturados.json.")