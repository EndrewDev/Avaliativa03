import socket

host = input('\nInforme o nome do Host ou URL do site: ')

ip_host = socket.gethostbyname(host)

print(ip_host)