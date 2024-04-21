import json
import os.path
import socket
import ssl

from cryptography.hazmat.backends import default_backend

from common_functions import *
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
    conn = ssl.wrap_socket(conn, keyfile=client_key_path, certfile=client_cert_path,
                           cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_cert_path, ssl_version=ssl.PROTOCOL_TLSv1_2)
    conn.connect((HOST, PORT))
    return conn


def communicate_with_server(s_conn, server_cert_pem, user_CN):
    # server answer: has the user the right to take part in voting
    is_elig = s_conn.recv(1024).decode('utf-8')

    if is_elig == 'False':
        server_message = s_conn.recv(1024).decode('utf-8')
        s_server_message = s_conn.recv(1024)
        if verify_sign(server_message, s_server_message, server_cert_pem):
            if user_CN in server_message:
                print('FROM SERVER: ', server_message)
            else:
                print('SOMEONE TRIES TO DAMAGE YOUR CONNECTION!')
        else:
            print('SOMEONE HAS INTERCEPTED YOUR CONNECTION!')
        return

    elif is_elig == 'True':
        cand_list_json_str = s_conn.recv(1024).decode('utf-8')
        cand_list_s = s_conn.recv(1024)
        if verify_sign(cand_list_json_str, cand_list_s, server_cert_pem):
            cand_list = json.loads(cand_list_json_str)
            print(cand_list)

        else:
            print('BLANK WAS REPLACED!!!')
            return

    else:
        print('Unexpected message...')


if __name__ == "__main__":

    path_client_cert, path_client_key = get_client_cert_key()
    s_conn = connect_to_server(path_client_cert, path_client_key)
    #print(s_conn.getpeercert())
    with open(path_client_cert, 'r') as f:
        client_cer = f.read()
        user_CN = get_common_name_from_pem(client_cer)

    server_pem_cer = der_cert_to_pem(s_conn.getpeercert(binary_form=True))
    #print(server_pem_cer)

    communicate_with_server(s_conn, server_pem_cer, user_CN)
