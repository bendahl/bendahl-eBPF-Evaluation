import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(1,101):
    sock.sendto(bytes(f"{i}\n", "utf-8"), ("192.168.60.1", 8008))
