from cryptography import x509
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64


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
    encrypted_msg = encryptor.encrypt(a_message.encode('utf-8'))
    #print(encrypted_msg)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    #print(encoded_encrypted_msg)
    return encoded_encrypted_msg


def decrypt_data(encoded_encrypted_msg, priv_key):
    """
    Public-key decryption
    :param encoded_encrypted_msg: encrypted data (base64)
    :param public_key: (PEM format)
    :return: decrypted data
    """
    rsaKey_priv = RSA.importKey(priv_key)
    encryptor = PKCS1_OAEP.new(rsaKey_priv)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    #print(decoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    #print(decoded_decrypted_msg)
    return decoded_decrypted_msg.decode('utf-8')


def sign_data(data: str, private_key):
    """
    :param data: to be signed
    :param private_key: private key in PEM format
    :return: digital signature (bytes)
    """
    rsaKey_priv = RSA.importKey(private_key)
    signer = PKCS1_v1_5.new(rsaKey_priv)
    digest = SHA256.new()
    # It's being assumed the data is base64 encoded, so it's decoded before updating the digest
    digest.update(base64.b64encode(data.encode("utf-8")))
    sign = signer.sign(digest)
    return base64.b64encode(sign)


def verify_sign(data_to_ver: str, signature: bytes, public_key):
    """
    :param data_to_ver: verifiable data
    :param signature: signed data (base64)
    :param public_key: key in PEM format
    :return: return 'True' if signature is valid, else 'False'
    """
    digest = SHA256.new()
    digest.update(base64.b64encode(data_to_ver.encode('utf-8')))
    rsaKey_pub = RSA.importKey(public_key)
    verifier = PKCS1_v1_5.new(rsaKey_pub)

    return verifier.verify(digest, base64.b64decode(signature))


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
