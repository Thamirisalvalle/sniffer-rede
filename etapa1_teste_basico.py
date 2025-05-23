# Definindo a função que processará os pacotes capturados
# Importando a função sniff da biblioteca Scapy
from scapy.all import sniff

# Importando os protocolos IP da biblioteca Scapy
from scapy.layers.inet import IP

# Função que irá analisar se o pacote é do tipo IP
def analisar_pacote(pacote):
    if IP in pacote:
        # Se o pacote for do tipo IP, exibe informações sobre o pacote
          print(f"Origem: {pacote[IP].src} -> {pacote[IP].dst}")
    else:
          # Se o pacote não for do tipo IPv4, exibe uma mensagem padrão
          print("Pacote sem IPv4")


    # Exibe um resumo simples do pacote capturado
    #print(pacote.summary())

# Inicia a captura de 5 pacotes
sniff(prn=analisar_pacote, count=5)