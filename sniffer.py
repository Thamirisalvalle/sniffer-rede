# Importando as funções e classes necessárias do Scapy
from scapy.all import sniff, IP, IPv6, TCP, UDP
# Importando a classe Counter para contagem de pacotes
from collections import Counter

# Importando a biblioteca CSV para salvar os dados em um arquivo
import csv

# Protocolo a ser filtrado: "TCP", "UDP" ou "Outro" (deixe como None para capturar tudo)
PROTOCOLO_FILTRADO = None

# Contadores de pacotes capturados por protocolo
contador_tcp = 0
contador_udp = 0
contador_outro = 0

# Contadores para IPs de origem e destino
ip_origem_counter = Counter()
ip_destino_counter = Counter()

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
            return "Privado"  # Faixa privada 172.16.0.0/12
        elif partes[0] == 192 and partes[1] == 168:
            return "Privado" # Faixa privada 192.168.0.0/16
        elif partes[0] >= 224 and partes[0] <= 239:
            return "Multicast" # Faixa 224.0.0.0 a 239.255.255.255
        else:
            return "Público" # Fora das faixas privadas, é público

# Função chamada para cada pacote capturado
def analisar_pacote(pacote):
    global contador_tcp, contador_udp, contador_outro
    global ip_origem_counter, ip_destino_counter

    protocolo_texto = ""
    
    # Verifica se o pacote é do tipo IPv4
    if IP in pacote:
        # Para pacotes IPv4
        ip_origem = pacote[IP].src # Endereço de origem (quem enviou)
        ip_destino = pacote[IP].dst # Endereço de destino (quem deve receber)
        protocolo_texto = "IPv4"
    # Verifica se o pacote é do tipo IPv6
    elif IPv6 in pacote:
        # Para pacotes IPv6
        ip_origem = pacote[IPv6].src # Endereço de origem (quem enviou)
        ip_destino = pacote[IPv6].dst# Endereço de destino (quem deve receber)
        protocolo_texto = "IPv6"
    else:
        return

    # Atualiza os contadores de IP
    ip_origem_counter[ip_origem] += 1
    ip_destino_counter[ip_destino] += 1

    # Verifica se o pacote contém protocolo TCP ou UDP
    if TCP in pacote:
        protocolo = "TCP" # Protocolo TCP
        porta_origem = pacote[TCP].sport
        porta_destino = pacote[TCP].dport
        contador_tcp += 1 # Atualiza o contador de pacotes TCP
    elif UDP in pacote:
        protocolo = "UDP" # Protocolo UDP
        porta_origem = pacote[UDP].sport
        porta_destino = pacote[UDP].dport
        contador_udp += 1 # Atualiza o contador de pacotes UDP
    else:
        protocolo = "Outro"
        porta_origem = "N/A"
        porta_destino = "N/A"
        contador_outro += 1 # Atualiza o contador de pacotes de outros protocolos

    tipo_origem = classificar_ip(ip_origem)  # Classifica o IP de origem
    tipo_destino = classificar_ip(ip_destino)  # Classifica o IP de destino

    # Exibe o resultado formatado
    if PROTOCOLO_FILTRADO is None or protocolo == PROTOCOLO_FILTRADO:
        print(f"[{protocolo_texto}] {ip_origem}:{porta_origem} ({tipo_origem}) -> {ip_destino}:{porta_destino} ({tipo_destino}) | Protocolo: {protocolo}")
        print(f"Contadores: TCP: {contador_tcp}, UDP: {contador_udp}, Outro: {contador_outro}\n")

#print("Testando o bug")

# Função para exibir os 5 principais IPs de origem e destino
def exibir_top_5():
    print("\n== Top 5 IPs de origem ==")
    for ip, count in ip_origem_counter.most_common(5):
        print(f"protocolo_texto {ip}: {count} pacotes")
    
    print("\n== Top 5 IPs de destino ==")
    for ip, count in ip_destino_counter.most_common(5):
        print(f"{ip}: {count} pacotes")

def salvar_em_csv():
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
           print("Estatísticas salvas em 'estatisticas_trafego.csv'")

# Inicia a captura dos pacotes da rede (pressione Ctrl+C para parar)
print("Iniciando a captura de pacotes... (Pressione CTRL+C para parar)\n")
try:
    #sniff(prn=analisar_pacote, store=0)
#except KeyboardInterrupt:
#print("\nParando a captura...")
#    exibir_top_5()
  sniff(prn=analisar_pacote, store=0)
except KeyboardInterrupt:
  print("\nParando a captura...")
exibir_top_5()
print("\nSalvando estatísticas em 'estatisticas_trafego.csv'...")
salvar_em_csv()
print("Análise completa! Obrigado por usar o analisador de tráfego.")