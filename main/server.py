import json
import socket
import ssl
import threading
import time

import psycopg2

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
    conn = psycopg2.connect(host='localhost',
                            dbname='postgres',
                            user='postgres',
                            password='12345678',
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


def check_is_eligible(client_cert: dict, db_conn, db_cur):
    """
    Checks whether the user has the right to vote
    :param client_cert: client certificate
    :return: Returns 'True' if user is eligible to vote, else 'False'
    """
    # cert = {subject, issuer, version, serialNumber, notBefore, notAfter}
    #         subject = {'countryName', 'stateOrProvinceName', 'localityName', 'organizationName', 'commonName'}
    user_name = client_cert['subject'][-1][-1][-1]

    db_cur.execute('''
        SELECT CASE WHEN EXISTS (SELECT 1 FROM eligible_voters WHERE name = '{}') THEN true ELSE false END;
    '''.format(user_name))

    is_present = db_cur.fetchone()[0]
    return is_present


def threaded_client(c_conn, db_conn, db_cur):
    client_cert = c_conn.getpeercert()
    is_eligible = check_is_eligible(client_cert, db_conn, db_cur)
    print('result:', is_eligible)


def close_connection_to_db(conn, cur):
    cur.close()
    conn.close()


if __name__ == "__main__":
    server_sock = server_net_prep()

    cand_list = {'Cand1': 'Ivanov',
                 'Cand2': 'Smirnov',
                 'Cand3': 'Petrov'}

    db_conn, db_cur = connect_to_db()

    num_conn = 0
    # TODO: add timer till the end of voting
    while num_conn < 3:
        c_conn, client_address = server_sock.accept()
        client_handler = threading.Thread(
            target=threaded_client,
            args=(c_conn, db_conn, db_cur)
        )
        client_handler.start()
        num_conn += 1

    close_connection_to_db(db_conn, db_cur)
