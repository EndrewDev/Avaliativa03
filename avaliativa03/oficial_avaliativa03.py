# Definir o formato do cabeçalho do arquivo .cap
magic_number = bytes.fromhex('a1b2c3d4')
major_version = (2).to_bytes(2, byteorder='big')
minor_version = (4).to_bytes(2, byteorder='big')
reserved1 = (0).to_bytes(4, byteorder='big')
reserved2 = (0).to_bytes(4, byteorder='big')
snap_len = (65535).to_bytes(4, byteorder='big')
fcs_link_type = (0).to_bytes(4, byteorder='big')  # Exemplo, valores fictícios

file_name = None

while True:
    # Opção
    opcao = input("1 - cap1\n2 - cap2\n")

    if opcao == "1":
        file_name = opcao
        break 
    elif opcao == "2":
        file_name = opcao
        break
    else:
        print("Não existe esse opção. Tente Novamente.")
        continue

# Abrir o arquivo para escrita binária
with open(file_name + '.cap', 'wb') as file:
    # Escrever o cabeçalho do arquivo .cap
    print()
    print('O formado cabeçalho do arquivo:')
    print(f'magic_number: {file.write(magic_number)}')
    print('--------------------------------------------')
    print(f'major_version: {file.write(major_version)}')
    print('--------------------------------------------')
    print(f'minor_version {file.write(minor_version)}')
    print('--------------------------------------------')
    print(f'resrved1: {file.write(reserved1)}')
    print('--------------------------------------------')
    print(f'reserved2: {file.write(reserved2)}')
    print('--------------------------------------------')
    print(f'snap_len: {file.write(snap_len)}')
    print('--------------------------------------------')
    print(f'fcs_link_type: {file.write(fcs_link_type)}')

# Definir os campos do cabeçalho do pacote
timestamp_seconds = (1234567890).to_bytes(4, byteorder='big')  # Exemplo de valor para segundos
timestamp_micros = (987654321).to_bytes(4, byteorder='big')  # Exemplo de valor para microssegundos
length_captured = (1500).to_bytes(4, byteorder='big')  # Exemplo de valor para comprimento capturado
length_original = (1540).to_bytes(4, byteorder='big')  # Exemplo de valor para comprimento original
packet_data = b'abcdef'  # Exemplo de dados do pacote

# Abrir o arquivo para escrita binária
with open(file_name + '.bin', 'wb') as file:
    # Escrever o cabeçalho do pacote
    print()
    print('E o formato de cada pacote que segue o cabeçalho do arquivo:')
    print(f'timestamp_seconds: {file.write(timestamp_seconds)}')
    print("--------------------------------------------")
    print(f'timestamp_micro: {file.write(timestamp_micros)}')
    print("--------------------------------------------")
    print(f'length_captured: {file.write(length_captured)}')
    print("--------------------------------------------")
    print(f'length_original: {file.write(length_original)}')
    print("--------------------------------------------")
    print(f'packet_data: {file.write(packet_data)}')

# Abrir o arquivo de captura binária para leitura
with open(file_name + '.cap', 'rb') as file:
    # Ler o cabeçalho do arquivo (caso seja necessário)
    header_bytes = file.read(24)  # Tamanho do cabeçalho do arquivo é 24 bytes
    # Exibir o conteúdo do cabeçalho do arquivo, se necessário
    # print("Conteúdo do cabeçalho do arquivo:", header_bytes.hex())

    # Variáveis para as métricas
    maior_tamanho_tcp = 0
    pacotes_incompletos = 0
    total_pacotes_udp = 0
    total_tamanho_udp = 0
    ip_tráfego_máximo = None
    ip_tráfego_máximo_quantidade = 0
    ip_interagiu_outros_ips = set()

    # Loop para ler os pacotes do arquivo
    while True:
        # Ler o cabeçalho do pacote (tamanho fixo de 20 bytes para IPv4)
        pacote_bytes = file.read(20)
        if not pacote_bytes:
            break  # Se não houver mais bytes para ler, sair do loop

        # Exibir o conteúdo do cabeçalho do pacote
        # print("Conteúdo do cabeçalho do pacote:", pacote_bytes.hex())

        # Interpretar os campos do cabeçalho do pacote IPv4
        # Aqui você precisaria implementar a lógica para analisar os bytes e extrair as informações necessárias

        # Exemplo simplificado de cálculo do tamanho do pacote TCP
        # (considerando que o protocolo seja TCP e que o tamanho do pacote TCP esteja nos bytes 16-17 do cabeçalho)
        tipo_protocolo = pacote_bytes[9]  # Índice 9 é onde está o tipo de protocolo (IPv4)
        if tipo_protocolo == 6:  # TCP
            tamanho_tcp = int.from_bytes(pacote_bytes[16:18], byteorder='big')
            if tamanho_tcp > maior_tamanho_tcp:
                maior_tamanho_tcp = tamanho_tcp

        # Exemplo de verificação de pacotes incompletos (se SnapLen não capturou o pacote completo)
        snap_len = int.from_bytes(header_bytes[16:20], byteorder='big')
        comprimento_capturado = int.from_bytes(pacote_bytes[2:4], byteorder='big')
        if comprimento_capturado > snap_len:
            pacotes_incompletos += 1

        # Exemplo de cálculo do tamanho médio dos pacotes UDP
        if tipo_protocolo == 17:  # UDP
            total_pacotes_udp += 1
            comprimento_pacote = int.from_bytes(pacote_bytes[2:4], byteorder='big')
            total_tamanho_udp += comprimento_pacote

        # Exemplo de contagem do tráfego entre IPs
        endereço_origem = pacote_bytes[12:16]
        endereço_destino = pacote_bytes[16:20]
        ip_interagiu_outros_ips.add(endereço_origem)
        ip_interagiu_outros_ips.add(endereço_destino)

    # Calcular o tamanho médio dos pacotes UDP
    tamanho_médio_udp = total_tamanho_udp / total_pacotes_udp if total_pacotes_udp > 0 else 0

    # Encontrar o par de IP com maior tráfego
    for ip in ip_interagiu_outros_ips:
        quantidade = 0
        file.seek(0)  # Voltar para o início do arquivo
        while True:
            pacote_bytes = file.read(20)  # Ler o cabeçalho do pacote
            if not pacote_bytes:
                break

            endereço_origem = pacote_bytes[12:16]
            endereço_destino = pacote_bytes[16:20]
            if ip == endereço_origem or ip == endereço_destino:
                quantidade += 1

        if quantidade > ip_tráfego_máximo_quantidade:
            ip_tráfego_máximo = ip
            ip_tráfego_máximo_quantidade = quantidade

    # Exibir os resultados
    print()
    print("Desenvolva um programa que leia um arquivo capturado pelo tcpdump e responda:")
    print("Tamanho do maior pacote TCP capturado:", maior_tamanho_tcp)
    print("Quantidade de pacotes incompletos:", pacotes_incompletos)
    print("Tamanho médio dos pacotes UDP capturados:", tamanho_médio_udp)
    print("Par de IPs com maior tráfego entre eles:", ip_tráfego_máximo)
    print("Quantidade de IPs com os quais o IP da interface capturada interagiu:", len(ip_interagiu_outros_ips))