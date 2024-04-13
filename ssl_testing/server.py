import socket
import ssl
from ssl import *
#
# SERVER_HOST = 'localhost'
# SERVER_PORT = 9999
#
# #context = ssl.create_default_context(purpose=Purpose.CLIENT_AUTH, capath='ca_cert')
#
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_cert_chain('./ca_cert/server.cer', './ca_cert/server.key')
#
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
#     sock.bind((SERVER_HOST, SERVER_PORT))
#     sock.listen(5)
#     with context.wrap_socket(sock, server_side=True) as ssock:
#         conn, addr = ssock.accept()

import socket
import ssl

HOST = "127.0.0.1"
PORT = 60000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server = ssl.wrap_socket(
    server, server_side=True, keyfile="../ca_cert/server.key", certfile="../ca_cert/server.cer"
)

if __name__ == "__main__":
    server.bind((HOST, PORT))
    server.listen(0)

    while True:
        connection, client_address = server.accept()
        while True:
            data = connection.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode('utf-8')}")