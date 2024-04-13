# import socket
# import ssl
# from ssl import *
#
# SERVER_HOST = 'localhost'
# SERVER_PORT = 9999
#
# #context = ssl.create_default_context(purpose=Purpose.SERVER_AUTH, capath='ca_cert')
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# context.load_verify_locations('ca_cert')
#
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
#     with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
#         print(ssock.version())

import socket
import ssl
from server import HOST as SERVER_HOST
from server import PORT as SERVER_PORT
#
# SERVER_HOST = 'localhost'
# SERVER_PORT = 5555

HOST = "127.0.0.1"
PORT = 60002


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

client = ssl.wrap_socket(client, keyfile="../ca_cert/client.key", certfile="../ca_cert/client.cer",
                         cert_reqs=ssl.CERT_REQUIRED, ca_certs="../ca_cert/ca.cer", ssl_version=ssl.PROTOCOL_TLSv1_2)

if __name__ == "__main__":
    client.bind((HOST, PORT))
    client.connect((SERVER_HOST, SERVER_PORT))

    while True:
        from time import sleep

        client.send("Hello World!".encode("utf-8"))
        sleep(20)