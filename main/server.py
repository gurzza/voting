import json
import socket
import ssl
import threading

HOST = "127.0.0.1"
PORT = 60000
MAX_CONNECTIONS = 10
SERVER_CERT_PATH = '../ca_cert/server.cer'
SERVER_KEY_PATH = '../ca_cert/server.key'
CA_CERT_PATH = '../ca_cert/ca.cer'


def server_net_prep():
    """
    Server-side preparation for future connection from clients
    :return: tls-socket
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_sock = ssl.wrap_socket(
        server_sock, keyfile=SERVER_KEY_PATH, certfile=SERVER_CERT_PATH,
        cert_reqs=ssl.CERT_REQUIRED, ca_certs=CA_CERT_PATH, ssl_version=ssl.PROTOCOL_TLSv1_2)

    server_sock.bind((HOST, PORT))
    server_sock.listen(MAX_CONNECTIONS)

    return server_sock


def threaded_client(c_conn):
    print('ok')


if __name__ == "__main__":
    server_sock = server_net_prep()

    cand_list = {'Cand1': 'Ivanov',
                 'Cand2': 'Smirnov',
                 'Cand3': 'Petrov'}

    while True:
        c_conn, client_address = server_sock.accept()
        client_handler = threading.Thread(
            target=threaded_client,
            args=(c_conn,)
        )
        client_handler.start()
        #while True:
        #c_conn.send(bytes(json.dumps(cand_list), 'utf-8'))
        print(c_conn.getpeercert())
