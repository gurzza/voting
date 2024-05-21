import json
import os.path
import random
import socket
import ssl

from _socket import SHUT_RDWR
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
        if os.path.isfile(path_to_cert) and path_to_cert.find('.cer') != -1:
            is_find_cert = True
        else:
            print('Incorrect path \'{}\' or file! Try one more time...'.format(path_to_cert))

    is_find_key = False
    while not is_find_key:
        path_to_key = input('Enter path to your private key: ')
        if os.path.isfile(path_to_key) and path_to_key.find('.key') != -1:
            is_find_key = True
        else:
            print('Incorrect path \'{}\' or file! Try one more time...'.format(path_to_key))

    return path_to_cert, path_to_key


def get_password(enc_priv_key_file):
    """
    Find out real password to encrypted private key
    :param enc_priv_key: path to encrypted private key
    :return: password
    """
    with open(enc_priv_key_file, 'r') as f:
        enc_priv_key = f.read()
    is_corr_password = False
    password = ''
    while not is_corr_password:
        password = input('Enter your password to the private key: ')
        try:
            RSA.importKey(enc_priv_key, passphrase=password)
            is_corr_password = True
        except ValueError:
            print('WRONG PASSWORD! Try one more time...')
    return password


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

    password = get_password(client_key_path)
    # Load the certificate and private key into the SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path, password=password)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_cert_path)

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(conn)
    conn.connect((HOST, PORT))
    return conn


def make_choice(empty_bulletin):
    is_agree = False
    candidates = empty_bulletin.values()

    while not is_agree:
        candidates_copy = list(candidates).copy()
        bulletin = []
        while candidates_copy:
            print("Choose the most desirable candidate from the remaining list:")
            for i in range(len(candidates_copy)):
                print(i + 1, '. ', candidates_copy[i], sep='')
            cand_n = int(input())
            if cand_n > len(candidates_copy) or cand_n < 1:
                print('Incorrect number!')
                continue
            bulletin.append(candidates_copy[cand_n - 1])
            del candidates_copy[cand_n - 1]

        print('Your choices (from top to bottom):')
        for i in range(len(bulletin)):
            print(i + 1, ': ', bulletin[i], sep='')

        choice = int(input('Are you sure in your choices? To commit enter \'1\', else \'2\': '))
        is_agree = True if choice == 1 else False

    #print(bulletin)
    return bulletin


def bulletin_to_numbers(bulletin: list, cand_ordered: list):
    """
    format: pos in original list +1, 00; pos in original list +1, 00
    :param bulletin: candidates ordered by VOTER
    :param cand_ordered: original list of candidates
    """
    num_bulletin = ''

    #i = 0
    for cand in bulletin:
        #i += 1
        #num_bulletin += str(i)
        num_bulletin += str(cand_ordered.index(cand) + 1)
        # FIXME: bad idea for if amount of candidates >= 10
        num_bulletin += '00'

    return num_bulletin  #+ str(random.randrange(100, 999))


def communicate_with_server(s_conn, server_cert_pem, user_CN, voter_priv_key):
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
        # get candidates list from server and check signature (currently: server key)
        cand_list_json_str = s_conn.recv(1024).decode('utf-8')
        cand_list_s = s_conn.recv(1024)

        print('Log: Opening file with public key for bulletin authority')
        try:
            with open('../ca_cert/bulletin.cer', 'r') as f:
                bulletin_pub_key = f.read()
        #FIXME: doesn't close socket correctly (other end prints 'FAKE SIGNATURE')
        except FileNotFoundError:
            s_conn.shutdown(1)
            s_conn.close()
            print('Can\'t find file...')
            return

        if verify_sign(cand_list_json_str, cand_list_s, bulletin_pub_key):
            cand_list = json.loads(cand_list_json_str)
            # print('List of all candidates:')
            # for cand_num in cand_list.keys():
            #     print(cand_num, ': ', cand_list[cand_num], sep='')
            bulletin = make_choice(cand_list)

            # convert bulletin to numerical form, then encrypt, sign and send
            with open('../ca_cert/counter.cer', 'r') as f:
                counter_pub_key = f.read()

            bulletin_num = bulletin_to_numbers(bulletin, list(cand_list.values()))
            # encrypt bulletin
            bulletin_num_enc = encrypt_data(bulletin_num, counter_pub_key)
            # sign encrypted bulletin
            bulletin_num_enc_s = sign_data(bulletin_num_enc, voter_priv_key, with_password=True)

            s_conn.send(bulletin_num_enc)
            s_conn.send(bulletin_num_enc_s)

            print('Your bulletin hash is:', hash_calculation(bulletin_num_enc))
            print(s_conn.recv(1024).decode('utf-8'))

        else:
            print('BULLETIN WAS REPLACED!')
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

    with open(path_client_key, 'r') as f:
        priv_key = f.read()

    server_pem_cer = der_cert_to_pem(s_conn.getpeercert(binary_form=True))
    #print(server_pem_cer)

    communicate_with_server(s_conn, server_pem_cer, user_CN, priv_key)
