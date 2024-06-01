import psycopg2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

from cryptography.hazmat.primitives.serialization import load_pem_private_key


def get_commonName(cert: dict):
    """
    :return: (bytes)
    """
    return cert['subject'][-1][-1][-1]


def encrypt_data(a_message, pub_key):
    """
    Public-key encryption
    :param a_message: data to encrypt
    :param private_key: (PEM format)
    :return: encrypted data (base64)
    """
    rsaKey_pub = RSA.importKey(pub_key)
    encryptor = PKCS1_OAEP.new(rsaKey_pub)
    if isinstance(a_message, int):
        a_message = str(a_message)
    encrypted_msg = encryptor.encrypt(a_message.encode('utf-8'))
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg


def decrypt_data(encoded_encrypted_msg, priv_key, with_password=False):
    """
    Public-key decryption
    :param encoded_encrypted_msg: encrypted data (base64)
    :param public_key: (PEM format)
    :param with_password: with or without password (bool)
    :return: decrypted data
    """
    if with_password:
        is_corr_password = False
        while not is_corr_password:
            password = input('Enter your password to the private key: ')
            try:
                rsaKey_priv = RSA.importKey(priv_key, passphrase=password)
                is_corr_password = True
            except ValueError:
                print('WRONG PASSWORD! Try one more time...')
    else:
        rsaKey_priv = RSA.importKey(priv_key, passphrase=None)
    encryptor = PKCS1_OAEP.new(rsaKey_priv)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg.decode('utf-8')


def decrypt_data_list(encoded_encrypted_msg_list, priv_key):
    """
    Public-key decryption
    :param encoded_encrypted_msg_list: encrypted list of data (base64)
    :param private_key: (PEM format)
    :return: decrypted data
    """

    is_corr_password = False
    while not is_corr_password:
        password = input('Enter your password to the private key: ')
        try:
            rsaKey_priv = RSA.importKey(priv_key, passphrase=password)
            is_corr_password = True
        except ValueError:
            print('WRONG PASSWORD! Try one more time...')

    encryptor = PKCS1_OAEP.new(rsaKey_priv)
    dec_votes = []
    for enc_vote in encoded_encrypted_msg_list:
        decoded_encrypted_msg = base64.b64decode(enc_vote[0].encode('utf-8'))
        #print(decoded_encrypted_msg)
        decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
        #print(decoded_decrypted_msg)
        dec_votes.append(decoded_decrypted_msg.decode('utf-8'))  #[:-3])  # remove randomness

    return dec_votes


def sign_data(data, private_key, with_password=False):
    """
    :param data: to be signed (str or bytes)
    :param private_key: private key in PEM format
    :return: digital signature (bytes)
    """
    if with_password:
        is_corr_password = False
        while not is_corr_password:
            password = input('Enter your password to the private key: ')
            try:
                rsaKey_priv = RSA.importKey(private_key, passphrase=password)
                is_corr_password = True
            except ValueError:
                print('WRONG PASSWORD! Try one more time...')
    else:
        rsaKey_priv = RSA.importKey(private_key, passphrase=None)
    signer = PKCS1_v1_5.new(rsaKey_priv)
    digest = SHA256.new()
    if isinstance(data, bytes):
        digest.update(base64.b64encode(data))
    else:
        digest.update(base64.b64encode(data.encode("utf-8")))
    sign = signer.sign(digest)
    return base64.b64encode(sign)


def verify_sign(data_to_ver, signature: bytes, public_key):
    """
    :param data_to_ver: verifiable data (str or bytes)
    :param signature: signed data (base64)
    :param public_key: key in PEM format
    :return: return 'True' if signature is valid, else 'False'
    """
    digest = SHA256.new()
    if isinstance(data_to_ver, bytes):
        digest.update(base64.b64encode(data_to_ver))
    else:
        digest.update(base64.b64encode(data_to_ver.encode('utf-8')))
    rsaKey_pub = RSA.importKey(public_key)
    verifier = PKCS1_v1_5.new(rsaKey_pub)

    return verifier.verify(digest, base64.b64decode(signature))


def verify_sign_list(enc_votes, signatures, public_key):
    verified_enc_votes = []
    verified_enc_votes_hash = []
    if len(enc_votes) != len(signatures):
        print('Log: Number of signatures is not equal to number of votes! Can\'t counting...')
        return verified_enc_votes

    len_enc_votes = len(enc_votes)
    for i in range(len_enc_votes):
        len_last_vote = len(str(i + 1))
        # 8 bytes
        str_last_vote = base64.b64encode(('0' * (4 - len_last_vote) + str(i + 1)).encode('utf-8')).decode('utf-8')
        signature = signatures[i]
        data_to_ver = enc_votes[i][0] + str_last_vote
        digest = SHA256.new()
        if isinstance(data_to_ver, bytes):
            digest.update(base64.b64encode(data_to_ver))
        else:
            digest.update(base64.b64encode(data_to_ver.encode('utf-8')))
        rsaKey_pub = RSA.importKey(public_key)
        verifier = PKCS1_v1_5.new(rsaKey_pub)

        if verifier.verify(digest, base64.b64decode(signature[0])):
            verified_enc_votes.append(enc_votes[i])
            verified_enc_votes_hash.append(hash_calculation(enc_votes[i][0]))
        else:
            print('Log: Vote {} with hash {} was substituted!'.format(i+1, hash_calculation(enc_votes[i][0])))

    return verified_enc_votes, verified_enc_votes_hash


def der_cert_to_pem(cert_der):
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    pem_certificate = cert.public_bytes(encoding=serialization.Encoding.PEM)
    return pem_certificate.decode('utf-8')


def der_cert_to_pem(cert_der):
    #cert_der = s_conn.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    pem_certificate = cert.public_bytes(encoding=serialization.Encoding.PEM)
    return pem_certificate.decode('utf-8')


def read_pub_key_from_cert(cert):
    """
    Extract public key from certificate
    :param cert: certificate (PEM format)
    :return: public key (PEM format)
    """
    cert_in_bytes = bytes(cert, 'utf-8')
    cert_obj = x509.load_pem_x509_certificate(cert_in_bytes)
    public_key_obj = cert_obj.public_key()
    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_key_string = public_pem.decode("utf-8")
    return pub_key_string


def get_common_name_from_pem(pem_certificate):
    cert = x509.load_pem_x509_certificate(pem_certificate.encode('utf-8'), default_backend())
    common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return common_name


def get_serialn_from_pem(pem_cert) -> str:
    cert = x509.load_pem_x509_certificate(pem_cert.encode('utf-8'), default_backend())
    return '0' + hex(cert.serial_number)[2:]


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


def close_connection_to_db(conn, cur):
    cur.close()
    conn.close()


def hash_calculation(text):
    """
    :param text: str or byte
    :return: SHA256
    """
    digest = SHA256.new()
    if isinstance(text, bytes):
        digest.update(base64.b64encode(text))
    else:
        digest.update(base64.b64encode(text.encode('utf-8')))
    return digest.hexdigest()



#def produce_hmac(message: str, key)

#
if __name__ == "__main__":
    with open("../ca_cert/client.key", "r") as f:
        priv_key = f.read()
    with open("../ca_cert/client.cer", "r") as f:
        cert = f.read()
        pub_key = read_pub_key_from_cert(cert)

    data = "hello, worlda"
    s = sign_data(data, priv_key)
    #print(s)
    print(verify_sign(data, s, pub_key))
    # e = encrypt_data(data, pub_key)
    # print(decrypt_data(e, priv_key))
