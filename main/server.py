import ast
import json
import socket
import ssl
import threading
import time
import psycopg2

from common_functions import *

HOST = "127.0.0.1"
PORT = 60000
MAX_CONNECTIONS = 10
SERVER_CERT_PATH = '../ca_cert/server.cer'
SERVER_KEY_PATH = '../ca_cert/server.key'
CA_CERT_PATH = '../ca_cert/ca.cer'


def connect_to_db():
    """
    Connects to DB (localhost)
    :return: connection, cursor
    """
    conn = psycopg2.connect(host='localhost', dbname='postgres',
                            user='postgres', password='12345678',
                            port=5432)

    cur = conn.cursor()
    return conn, cur


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


def check_is_eligible(client_cert, db_conn, db_cur):
    """
    Checks whether the user has the right to vote
    :param client_cert: client certificate (PEM)
    :return: Returns 'True' if user is eligible to vote, else 'False'
    """
    # cert = {subject, issuer, version, serialNumber, notBefore, notAfter}
    #         subject = {'countryName', 'stateOrProvinceName', 'localityName', 'organizationName', 'commonName'}
    user_name = get_common_name_from_pem(client_cert)  #['subject'][-1][-1][-1]

    db_cur.execute('''
        SELECT CASE WHEN EXISTS (SELECT 1 FROM eligible_voters WHERE name = '{}') THEN true ELSE false END;
    '''.format(user_name))

    is_present = db_cur.fetchone()[0]
    return is_present


def parse_bulletin(bulletin_num, cand_names):
    """
    input: pos in original list +1, 00; pos in original list +1, 00; ...
    """
    i = 0
    curr_pos = 0
    bulletin_list = []
    while curr_pos < len(bulletin_num):
        # FIXME: bad idea if amount of candidates >= 10
        pos_b_length = bulletin_num.find('00',
                                         curr_pos) - curr_pos  # pos_in_bulletin_length: the length of the number that represents candidate position in bulletin (ex: for 10 length 2)
        cand_int = int(bulletin_num[curr_pos: curr_pos + pos_b_length])
        bulletin_list.append(cand_names[cand_int - 1])
        curr_pos += pos_b_length + 2  # +2 from len('00')

    return bulletin_list


def threaded_client(c_conn, db_conn, db_cur, priv_key, cand_list):
    client_cert = der_cert_to_pem(c_conn.getpeercert(binary_form=True))
    is_eligible = check_is_eligible(client_cert, db_conn, db_cur)

    if not is_eligible:
        c_conn.send('False'.encode())
        message = '{} has not right to take part in this voting!'.format(get_common_name_from_pem(client_cert))
        c_conn.send(message.encode('utf-8'))
        # HINT: sign this message to avoid MITM (ex: someone intercept your connection and without signature
        #  can break up connection)
        s_message = sign_data(message, priv_key)
        c_conn.send(s_message)
        return

    else:
        c_conn.send('True'.encode())
        # send candidates list and signature
        # TODO: add read from file (?)
        cand_list_json_str = json.dumps(cand_list)
        c_conn.send(cand_list_json_str.encode('utf-8'))
        cand_list_s = sign_data(cand_list_json_str, priv_key)
        c_conn.send(cand_list_s)

        # get bulletin from voter and check signature
        bulletin_num_enc = c_conn.recv(2048).decode('utf-8')
        bulletin_num_enc_s = c_conn.recv(1024)
        if not verify_sign(bulletin_num_enc, bulletin_num_enc_s, client_cert):
            print('FAKE SIGNATURE!')
            return
        else:
            #print('EVERYTHING IS OK')
            # FIXME: change server_priv_key to departure that will count votes
            # remove randomness
            bulletin_num = decrypt_data(bulletin_num_enc, priv_key)[:-3]
            #
            bulletin_list = parse_bulletin(bulletin_num, list(cand_list.values()))
            print(bulletin_list)


def close_connection_to_db(conn, cur):
    cur.close()
    conn.close()


if __name__ == "__main__":
    # FIXME: read from file or sign file with candidates and check signature?
    # cand_list = {'Cand1': 'Green',
    #              'Cand2': 'Blue',
    #              'Cand3': 'Yellow'}

    with open("../bulletin/candidates.txt", 'r') as f:
        # ast.literal_eval: str -> dict
        cand_list = ast.literal_eval(f.read())
    cand_list_json_str = json.dumps(cand_list)

    with open("../bulletin/candidates.txt.signature", 'rb') as f:
        cand_list_signature = f.read()

    with open("../ca_cert/bulletin.cer", 'r') as f:
        bulletin_public_key = f.read()

    if not verify_sign(cand_list_json_str, cand_list_signature, bulletin_public_key):
        print('BULLETIN WAS CORRUPTED! WE CAN\'T START VOTING!')

    else:  # if with signature everything okay
        server_sock = server_net_prep()

        db_conn, db_cur = connect_to_db()

        with open(SERVER_KEY_PATH, 'r') as f:
            priv_key = f.read()

        num_conn = 0
        # TODO: add timer till the end of voting
        while num_conn < 3:
            c_conn, client_address = server_sock.accept()
            client_handler = threading.Thread(
                target=threaded_client,
                args=(c_conn, db_conn, db_cur, priv_key, cand_list)
            )
            client_handler.start()
            num_conn += 1

        close_connection_to_db(db_conn, db_cur)
