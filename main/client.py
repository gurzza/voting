import json
import os.path
import socket
import ssl
from server import HOST as SERVER_HOST
from server import PORT as SERVER_PORT


def get_client_cert_key():
    """
        gets from user paths to voter certificate and private key
        :return: paths
    """
    path_to_cert, path_to_key = '', ''

    is_find_cert = False
    while not is_find_cert:
        path_to_cert = input('Enter path to your certificate: ')
        if os.path.isfile(path_to_cert):
            is_find_cert = True
        else:
            print('Incorrect path \'{}\'! Try one more time...'.format(path_to_cert))

    is_find_key = False
    while not is_find_key:
        path_to_key = input('Enter path to your private key: ')
        if os.path.isfile(path_to_key):
            is_find_key = True
        else:
            print('Incorrect path \'{}\'! Try one more time...'.format(path_to_key))

    return path_to_cert, path_to_key


def connect_to_server(client_cert_path: str, client_key_path: str, ca_cert_path='../ca_cert/ca.cer'):
    """
    Connects to server
    :param client_cert_path: path to client certificate
    :param client_key_path: path to client private key
    :param ca_cert_path: path to CA certificate
    :return: socket to server
    """

    PORT = SERVER_PORT
    HOST = SERVER_HOST

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    conn = ssl.wrap_socket(conn, keyfile=client_key_path, certfile=client_cert_path,
                           cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_cert_path, ssl_version=ssl.PROTOCOL_TLSv1_2)

    #conn.bind((HOST, PORT))
    conn.connect((HOST, PORT))

    return conn



if __name__ == "__main__":


    path_client_cert, path_client_key = get_client_cert_key()
    s_conn = connect_to_server(path_client_cert, path_client_key)
