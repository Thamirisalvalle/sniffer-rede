# Definindo a função que processará os pacotes capturados
# Importando a função sniff da biblioteca Scapy
from scapy.all import sniff

# Importando os protocolos IP, TCP, UDP e ICMP
from scapy.layers.inet import IP, TCP, UDP, ICMP

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
        return "Outro"

# Função que irá analisar se o pacote é do tipo IP
def analisar_pacote(pacote):
    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        protocolo = identificar_protocolo(pacote)
        # Exibe o conteúdo do pacote
        print(f"{ip_origem} -> {ip_destino} | Protocolo: {protocolo}")
    else:
        print("Pacote sem IPv4")

sniff(prn=analisar_pacote, count=5)
