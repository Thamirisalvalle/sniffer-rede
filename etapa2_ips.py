# Definindo a função que processará os pacotes capturados
# Importando a função sniff da biblioteca Scapy
from scapy.all import sniff

# Importando os protocolos IP da biblioteca Scapy
from scapy.layers.inet import IP

# Função que irá analisar se o pacote é do tipo IP
def analisar_pacote(pacote):
    if IP in pacote:
        # Se o pacote for do tipo IP, exibe informações sobre o pacote
        print(f"Origem: {pacote[IP].src} -> Destino: {pacote[IP].dst}")
    else:
        print("Pacote sem IPv4")

# Exibe um resumo simples dos 5 pacote capturado
sniff(prn=analisar_pacote, count=5)
