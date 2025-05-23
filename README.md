# 🛡️ Analisador de Tráfego de Rede com Python

Este projeto é um analisador simples de pacotes de rede feito com Python e a biblioteca **Scapy**. Ele captura pacotes em tempo real, identifica o protocolo, origem e destino, e exibe estatísticas úteis ao final da captura.

## 🚀 Funcionalidades

- Captura de pacotes IPv4 e IPv6 em tempo real.
- Identificação dos protocolos TCP, UDP ou outros.
- Contagem de pacotes por protocolo.
- Classificação dos endereços IP (Público, Privado, Link-Local, Multicast).
- Exibição dos 5 IPs mais frequentes de origem e destino.
- Salvamento das estatísticas em um arquivo `estatisticas_trafego.csv`.

---

## 📦 Requisitos

- [Python](https://www.python.org/) 3.6 ou superior
- Permissões de administrador (root) para capturar pacotes de rede (em Linux/macOS, usar `sudo`)
- [Scapy](https://scapy.net/) (`pip install scapy`)

---

## ⚙️ Instalação

1. Clone o repositório e entre no diretório do projeto:
   ```
   git clone https://github.com/Thamirisalvalle/sniffer-rede.git
   cd sniffer-rede
   ```

2. Crie um ambiente virtual (opcional, mas recomendado):
   ```
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. Instale as dependências:
   ```
   pip install scapy
   ```

## ▶️ Execução
Para iniciar a captura de pacotes:
    ```
    sudo python sniffer-rede.py
    ```
> Atenção: O sudo (Linux/macOS) ou executar como administrador (Windows) é necessário para acessar a interface de rede.


#### Usando ambiente virtual (venv)
Se você configurou um ambiente virtual, ative-o antes de rodar o script:

- Linux/macOS:
    ```
    source venv/bin/activate
    sudo python sniffer-rede.py
    ```

- Windows:
    ```
    .\venv\Scripts\Activate.ps1
    python sniffer-rede.py
    ```
> ⚠️ Nota: No Windows, geralmente não é necessário rodar como administrador para capturar pacotes com Scapy. Em sistemas Unix (Linux/macOS), o uso do sudo é necessário para permissões de rede.

#### Sem ambiente virtual
Se preferir executar diretamente (sem venv):

- Windows:

    ```
    python sniffer-rede.py
    ```

- Linux/macOS:
    ```
    sudo python sniffer-rede.py
    ```


>⚠️ Observações:
A análise é feita em tempo real e é essencial que seja executada em um ambiente que permita a captura de pacotes sem restrições de firewall ou regras de segurança restritivas.
Recomendamos testar em uma rede segura e conhecida para evitar captura de dados sensíveis em redes públicas.

## ⏹️ Parar a execução

Durante a execução, os pacotes capturados serão exibidos em tempo real no terminal Pressione `CTRL+C` para interromper a captura de pacotes.

#### 📈 Saída e Estatísticas:
O script exibe em tempo real os pacotes capturados, indicando:
- Endereços IP de origem e destino.
- Portas envolvidas.
- Tipo de IP (Privado, Público, Multicast, Link-local).
- Protocolo utilizado (TCP, UDP ou outro).

Ao final da captura, são exibidos:
- Os 5 IPs mais ativos de origem e destino.
- Classifica IPs (privado, público, multicast etc.).
- Contadores de pacotes por tipo (TCP, UDP, Outros).
- Um arquivo `estatisticas_trafego.csv` é gerado com essas informações

## 📝 Configuração
Você pode filtrar apenas pacotes TCP, UDP ou outros alterando o valor da variável `PROTOCOLO_FILTRADO` no início do código:

    
    PROTOCOLO_FILTRADO = "TCP"  # ou "UDP", "Outro", ou None para tudo
    

## 🗂️ Estrutura do Projeto

```
    sniffer-rede/
       ├── venv/    # Ambiente virtual (não incluído no controle de versão)
       ├── .gitignore   # Arquivos e pastas ignorados pelo Git
       ├── README.md    # Documentação do projeto
       ├── sniffer.py   # Script principal do sniffer
       └── estatisticas_trafego.csv     # Gerado automaticamente após execução 
```
## 🧼 .gitignore
Certifique-se de que o ambiente virtual e o arquivo .csv não sejam versionados:

    ```
    venv/
    estatisticas_trafego.csv
    __pycache__/
    *.pyc
    ```

## 📝 Licença
Este projeto é acadêmico e está aberto para fins educacionais. Sinta-se livre para estudar, modificar e reutilizar com créditos ao autor original.