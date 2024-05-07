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
VOTING_TIME_SEC = 60


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
    serialn = get_serialn_from_pem(client_cert)
    db_cur.execute('''
        SELECT CASE WHEN EXISTS (SELECT 1 FROM eligible_voters WHERE name = '{}' AND serialn = '{}') THEN true ELSE false END;
    '''.format(user_name, serialn))

    is_present = db_cur.fetchone()[0]
    return is_present


def add_vote_to_db(db_conn, db_cur, bulletin_num_enc, server_priv_key):
    """
    Sign encrypted bulletin and pass it to DB
    :param db_conn:
    :param db_cur:
    :param bulletin_num_enc: encrypted bulletin
    :param server_priv_key: server private key (to sign bulletin before pass it to DB)
    :return: None
    """
    bulletin_num_enc_s = sign_data(bulletin_num_enc, server_priv_key).decode('utf-8')
    db_cur.execute(" INSERT INTO enc_votes (vote, signature) VALUES (%s, %s)", (bulletin_num_enc, bulletin_num_enc_s))
    #(bulletin_num_enc_s)
    #print(bulletin_num_enc)
    print('Log: Added new record to DB')
    db_conn.commit()


def remove_voter_from_db(db_conn, db_cur, client_cert):
    """
    Remove voter from DB to prohibit voting more than one time
    """
    serialn = get_serialn_from_pem(client_cert)
    voter_name = get_common_name_from_pem(client_cert)
    db_cur.execute("DELETE FROM eligible_voters WHERE name = (%s) AND serialn = (%s)", (voter_name, serialn))
    db_conn.commit()
    print('Log: The user has voted successfully')


def threaded_client(c_conn, db_conn, db_cur, priv_key, cand_list_json_str, cand_s):
    client_cert = der_cert_to_pem(c_conn.getpeercert(binary_form=True))
    is_eligible = check_is_eligible(client_cert, db_conn, db_cur)

    if not is_eligible:
        c_conn.send('False'.encode())
        message = '{} has not right to take part in this voting or has already taken part in the voting!'.format(get_common_name_from_pem(client_cert))
        c_conn.send(message.encode('utf-8'))
        # HINT: sign this message to avoid MITM (ex: someone intercept your connection and without signature
        #  can break up connection)
        s_message = sign_data(message, priv_key)
        c_conn.send(s_message)
        return

    else:
        c_conn.send('True'.encode())
        # send candidates list and signature
        c_conn.send(cand_list_json_str.encode('utf-8'))
        c_conn.send(cand_s)

        # get bulletin from voter and check signature
        bulletin_num_enc = c_conn.recv(2048).decode('utf-8')
        bulletin_num_enc_s = c_conn.recv(1024)
        if not verify_sign(bulletin_num_enc, bulletin_num_enc_s, client_cert):
            print('FAKE SIGNATURE!')
            return
        else:
            add_vote_to_db(db_conn, db_cur, bulletin_num_enc, priv_key)
            remove_voter_from_db(db_conn, db_cur, client_cert)


#if __name__ == "__main__":
def server_job():
    # FIXME: read from file or sign file with candidates and check signature?
    # cand_list = {'Cand1': 'Green',
    #              'Cand2': 'Blue',
    #              'Cand3': 'Yellow'}

    try:
        print('Log: Opening file with candidates')
        with open("../bulletin/candidates", 'r') as f:
            # ast.literal_eval: str -> dict
            print('Log: File with candidates was opened successfully')
            cand_list = ast.literal_eval(f.read())
        cand_list_json_str = json.dumps(cand_list)

        print('Log: Opening file with signed candidates list')
        with open("../bulletin/candidates_signed", 'rb') as f:
            print('Log: File with signed candidates was opened successfully')
            cand_list_signature = f.read()

        print('Log: Opening file with public key for bulletin authority')
        with open("../ca_cert/bulletin.cer", 'r') as f:
            print('Log: Bulletin authority\'s certificate was opened successfully')
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
            server_sock.settimeout(VOTING_TIME_SEC)  # number in seconds
            while True:
                try:
                    c_conn, client_address = server_sock.accept()
                    client_handler = threading.Thread(
                        target=threaded_client,
                        args=(c_conn, db_conn, db_cur, priv_key, cand_list_json_str, cand_list_signature)
                    )
                    client_handler.start()
                except socket.timeout:
                    print('Time is over!')
                    break
            close_connection_to_db(db_conn, db_cur)

    except FileNotFoundError:
        print('FILE NOT FOUND! We can\'t start voting...')
