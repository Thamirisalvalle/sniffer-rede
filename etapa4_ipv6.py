# Importando a função sniff da biblioteca Scapy
# A função sniff permite capturar pacotes que passam pela interface de rede
from scapy.all import sniff

# Importando os protocolos da camada de rede e transporte
# IP: protocolo de internet (IPv4)
# TCP: protocolo confiável de transporte
# UDP: protocolo de transporte mais rápido, porém sem confirmação
# ICMP: usado para mensagens de controle, como o ping
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Importando suporte para pacotes Ipv6
from scapy.layers.inet6 import IPv6


# Função que identifica o protocolo utilizado no pacote
def identificar_protocolo(pacote):
    # Verifica se o pacote contém o protocolo TCP
    if TCP in pacote:
        return "TCP"
    # Verifica se o pacote contém o protocolo UDP
    elif UDP in pacote:
        return "UDP"
    # Verifica se o pacote contém o protocolo ICMP
    elif ICMP in pacote:
        return "ICMP"
    else:
        return "Outro" # Caso o pacote não tenha nenhum dos protocolos acima


# Função que analisa os pacotes capturados
def analisar_pacote(pacote):
    # Verifica se o pacote é do tipo IPv4
    if IP in pacote:
          ip_origem = pacote[IP].src  # Endereço de origem (quem enviou)
          ip_destino = pacote[IP].dst  # Endereço de destino (quem deve receber)
          protocolo = identificar_protocolo(pacote)  # Qual protocolo está sendo usado

          # Verifica se o pacote é do tipo TCP ou UDP para exibir as portas
          if protocolo == "TCP":
              porta_origem = pacote[TCP].sport
              porta_destino = pacote[TCP].dport
          elif protocolo == "UDP":
              porta_origem = pacote[UDP].sport
              porta_destino = pacote[UDP].dport
          else:
               porta_origem = porta_destino = "None" # Caso não seja TCP ou UDP

          # Exibe as informações
          if porta_origem and porta_destino:
              print(f"[IPv4] {ip_origem}:{porta_origem} -> {ip_destino}:{porta_destino} | Protocolo: {protocolo}")
          else:
              # Exibe apenas os IPs se não houver portas
              print(f"[IPv4] {ip_origem} -> {ip_destino} | Protocolo: {protocolo}")        

    # Verifica se o pacote é do tipo IPv6
    elif IPv6 in pacote:
          ip_origem = pacote[IPv6].src
          ip_destino = pacote[IPv6].dst
          protocolo = identificar_protocolo(pacote)

          if protocolo == "TCP":
              porta_origem = pacote[TCP].sport
              porta_destino = pacote[TCP].dport
          elif protocolo == "UDP":
              porta_origem = pacote[UDP].sport
              porta_destino = pacote[UDP].dport
          else:
              porta_origem = porta_destino = "None"
          
          if porta_origem and porta_destino:
              print(f"[IPv6] {ip_origem}:{porta_origem} -> {ip_destino}:{porta_destino} | Protocolo: {protocolo}")
          else:
              print(f"[IPv6] {ip_origem} -> {ip_destino} | Protocolo: {protocolo}")
          
    else:
          # Caso não seja um pacote IP ou IPv6 (pode ser ARP, por exemplo)
          print("Pacote sem IP")


    # Exibe um resumo simples do pacote capturado
    #print(pacote.summary())

# Inicia a captura de pacotes
# prn = função a ser chamada para cada pacote capturado
# count = número de pacotes a serem capturados
sniff(prn=analisar_pacote, count=5)