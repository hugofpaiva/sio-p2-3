import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import uuid
import base64
import PyKCS11
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat import primitives
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from datetime import datetime

import random


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

algorithms_options = [algorithms.AES, algorithms.Camellia]
hashes_options = [hashes.SHA256, hashes.SHA3_256]
cipher_modes_options = [modes.CTR, modes.CBC, modes.OFB, modes.CFB]


class Client:
    def __init__(self):
        self.MESSAGE_KEY = None
        self.DIGEST_KEY = None
        self.selected_algorithm = None
        self.selected_hash = None
        self.selected_mode = None
        self.root_ca_cert = self.load_cert('../server_certs/SIO_CA_1.crt')
        self.server_cert = None
        self.session = None
        self.user = None
        self.cert = None
        self.private_key = None
        self.id = uuid.uuid4().hex

    def load_cert(self, path):
        with open(path, 'rb') as f:
            data = f.read()
            return x509.load_pem_x509_certificate(data)

    def full_cert_verify(self, cert, issuer_cert):
        if cert.issuer == issuer_cert.issuer:
            if self.verify_date(cert) and self.verify_purpose(cert) and self.verify_signatures(cert, issuer_cert):
                print("All good")
                return True
            else:
                print("Can't verify certificate integraty")
        else:
            print("Can't chain to root CA")
        return False

    def verify_purpose(self, cert):
        if ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return True
        else:
            return False

    def verify_signatures(self, cert, issuer_cert):
        issuer_public_key = issuer_cert.public_key()

        try:
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False

    def verify_date(self, cert):
        if datetime.now() > cert.not_valid_after:
            return False
        else:
            return True

    def encrypt_uuid(self, id):
        return self.server_cert.public_key().encrypt(
            id,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def get_cc(self):
        # Verificar cc
        try:
            lib = '/usr/local/lib/libpteidpkcs11.so'

            if sys.platform.startswith('darwin'):
                lib = '/usr/local/lib/libpteidpkcs11.dylib'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)

            # List the first slot with present token
            slot = pkcs11.getSlotList(tokenPresent=True)[0]

        except:
            print("Cart not present")
            quit()

        all_attr = list(PyKCS11.CKA.keys())
        # Filter attributes
        all_attr = [e for e in all_attr if isinstance(e, int)]

        self.session = pkcs11.openSession(slot)

        for obj in self.session.findObjects():
            # Get object attributes
            attr = self.session.getAttributeValue(obj, all_attr)
            # Create dictionary with attributes
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

            if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                if attr['CKA_CERTIFICATE_TYPE'] != None:
                    self.cert = x509.load_der_x509_certificate(
                        bytes(attr['CKA_VALUE']))
                    self.user = self.cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[
                        0].value

        self.private_key = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

        return

    def main(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        self.get_cc()

        # Getting server certificate
        req = requests.get(f'{SERVER_URL}/api/auth')
        if req.status_code == 200:
            response = req.json()
            certificate = binascii.a2b_base64(
                response['certificate'].encode('latin'))
            self.server_cert = x509.load_pem_x509_certificate(certificate)

            if not self.full_cert_verify(self.server_cert, self.root_ca_cert):
                quit()

            nounce = os.urandom(32)

            response = {'nounce': binascii.b2a_base64(
                nounce).decode('latin').strip()}

            req = requests.post(f'{SERVER_URL}/api/auth', data=json.dumps(
                response).encode('latin'), headers={"content-type": "application/json"})

            if req.status_code == 200:
                response = req.json()
                signed_nounce = binascii.a2b_base64(
                    response['signed_nounce'].encode('latin'))

                try:
                    self.server_cert.public_key().verify(
                        signed_nounce,
                        nounce,
                        asymmetric.padding.PSS(
                            mgf=asymmetric.padding.MGF1(
                                primitives.hashes.SHA256()),
                            salt_length=asymmetric.padding.PSS.MAX_LENGTH
                        ),
                        primitives.hashes.SHA256()
                    )
                    print("Servidor Autenticado")
                except InvalidSignature:
                    quit()

            else:
                quit()

        else:
            quit()
    
        # User Authentication
        req = requests.get(f'{SERVER_URL}/api/cc_auth', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()
            nounce = binascii.a2b_base64(
                response['nounce'].encode('latin'))

            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

            signed_nounce = bytes(self.session.sign(
                self.private_key, nounce, mechanism))
        else:
            quit()

        response = {'certificate': binascii.b2a_base64(
            self.cert.public_bytes(Encoding.PEM)).decode('latin').strip(), 'signed_nounce': binascii.b2a_base64(signed_nounce).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/cc_auth', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code == 200:
            print("Utilizador Autenticado")
        else:
            print("Authentication of user error")
            quit()


        # Choosing options
        # Algorithm Option
        # 0. AES
        # 1. Camellia
        # 2. ChaCha20
        print("Generating Algorithms Options...")
        algs = []
        num_opt_alg = random.randint(1, len(algorithms_options))
        for i in range(0, num_opt_alg):
            rand = random.randint(0, len(algorithms_options)-1)
            while rand in algs:
                rand = random.randint(0, len(algorithms_options)-1)
            algs.append(rand)

        # Hash Option
        # 0 SHA3_256
        # 1 SHA3_512
        # 2 SHA256
        # 3 SHA512
        print("Generating Hash Options...")
        hashes = []
        num_opt_hash = random.randint(1, len(hashes_options))
        for i in range(0, num_opt_hash):
            rand = random.randint(0, len(hashes_options)-1)
            while rand in hashes:
                rand = random.randint(0, len(hashes_options)-1)
            hashes.append(rand)

        # Cipher Mode
        # 0.CTR
        # 1.CBC
        # 2.OFB
        # 3.CFB
        print("Generating Cipher Mode Options...")
        modes = []
        num_opt_modes = random.randint(1, len(cipher_modes_options))
        for i in range(0, num_opt_modes):
            rand = random.randint(0, len(cipher_modes_options)-1)
            while rand in modes:
                rand = random.randint(0, len(cipher_modes_options)-1)
            modes.append(rand)

        available_options = {'algorithms': algs,
                             'hashes': hashes, 'modes': modes}

        print("\nContacting Server")

        req = requests.post(f'{SERVER_URL}/api/protocols', data=json.dumps(
            available_options).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            print("Trading options error")
            quit()
        else:
            response = req.json()
            self.selected_algorithm = response['selected_algorithm']
            self.selected_hash = response['selected_hash']
            self.selected_mode = response['selected_mode']

        # DH Exchange
        self.dh_message_key()

        # DH Digest Key Exchange
        self.dh_digest_key()

        req = requests.get(f'{SERVER_URL}/api/protocols', headers={"Authorization": self.id})
        if req.status_code != 200:
            quit()
        else:
            response = req.json()
            digest = response['digest'].encode('latin')
            options = response['options'].encode('latin')
            iv = response['iv'].encode('latin')

            if self.verify_digest(self.DIGEST_KEY, self.selected_hash, options, digest):
                options, decryptor_var = self.decryptor(
                    self.selected_algorithm, self.selected_mode, self.MESSAGE_KEY, options, iv)

                options = json.loads(options.decode('latin'))
                if(self.selected_algorithm != options['selected_algorithm'] or self.selected_hash != options['selected_hash'] or self.selected_mode != options['selected_mode']):
                    print("MITM???")
                    quit()
            else:
                print("MITM???")
                quit()

        # Get a list of media files
        while True:
            media_list = None
            while True:
                req = requests.get(f'{SERVER_URL}/api/list', headers={"Authorization": self.id})
                if req.status_code == 200:
                    print("Got Server List")

                media_list = req.json()

                # Present a simple selection menu
                idx = 0
                print("MEDIA CATALOG\n")
                for item in media_list:
                    print(f'{idx} - {media_list[idx]["name"]} - Access: {media_list[idx]["has_access"]}')
                print("----")

                while True:
                    selection = input("Select a media file number (q to quit). If a song with no access is selected, a new license will be requested: ")
                    if selection.strip() == 'q':
                        req = requests.get(f'{SERVER_URL}/api/logout', headers={"Authorization": self.id})
                        if req.status_code == 200:
                            print("All done!")
                            sys.exit(0)

                    if not selection.isdigit():
                        continue

                    selection = int(selection)
                    if 0 <= selection < len(media_list):
                        break

                if not media_list[selection]['has_access']:
                    req = requests.get(f'{SERVER_URL}/api/get_music?id={media_list[selection]["id"]}', headers={"Authorization": self.id})
                    if req.status_code == 200:
                        print("Got new song!")
                        response = req.json()
                        digest = response['digest'].encode('latin')
                        license = response['license'].encode('latin')
                        iv = response['iv'].encode('latin')

                        if self.verify_digest(self.DIGEST_KEY, self.selected_hash, license, digest):
                            license, decryptor_var = self.decryptor(
                                self.selected_algorithm, self.selected_mode, self.MESSAGE_KEY, license, iv)
                            decoded_license = license.split(b"-")
                            decoded_license = base64.b64decode(decoded_license[0])
                            decoded_license = json.loads(decoded_license.decode('latin'))
                            with open("./licenses/"+str(decoded_license['serial_number_cc'])+"_"+str(decoded_license['media_id'])+"_"+str(decoded_license['date_of_expiration'])+".txt", "wb") as f:
                                f.write(license)
                                f.close()
                            
                    else:
                        print("Error getting license")
                else:
                    break


            # Example: Download first file
            media_item = media_list[selection]
            print(f"Playing {media_item['name']}")

            # Detect if we are running on Windows or Linux
            # You need to have ffplay or ffplay.exe in the current folder
            # In alternative, provide the full path to the executable
            if os.name == 'nt':
                proc = subprocess.Popen(
                    ['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
            else:
                proc = subprocess.Popen(
                    ['ffplay', '-i', '-'], stdin=subprocess.PIPE)

            decryptor_var = None

            # Get data from server and send it to the ffplay stdin through a pipe
            for chunk_id in range(media_item['chunks']):
                req = requests.get(
                    f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk_id}', headers={"Authorization": self.id})
                chunk = req.json()

                if chunk_id == 0:
                    iv = chunk['iv'].encode('latin')

                digest = chunk['digest'].encode('latin')

                data = chunk['data'].encode('latin')

                if not self.verify_digest(self.DIGEST_KEY, self.selected_hash, data, digest):
                    print("MITM???")
                    quit()

                if decryptor_var:
                    data, decryptor_var = self.decryptor(
                        self.selected_algorithm, self.selected_mode, self.MESSAGE_KEY, data, decryptor=decryptor_var)
                else:
                    data, decryptor_var = self.decryptor(
                        self.selected_algorithm, self.selected_mode, self.MESSAGE_KEY, data, iv)

                data = binascii.a2b_base64(data)

                try:

                    proc.stdin.write(data)
                except:
                    break

                if chunk_id % 5 == 0:
                    self.dh_digest_key()
                    self.dh_message_key()
                else:
                    self.MESSAGE_KEY = self.simple_digest(
                        self.selected_hash, self.MESSAGE_KEY)
                    self.DIGEST_KEY = self.simple_digest(
                        self.selected_hash, self.DIGEST_KEY)

    def encryptor(self, algorithm, mode, key, data):
        iv = os.urandom(algorithms_options[algorithm].block_size // 8)
        cipher = Cipher(algorithms_options[algorithm](
            key), cipher_modes_options[mode](iv))
        encryptor = cipher.encryptor()
        if mode == 1:
            padder = padding.PKCS7(
                algorithms_options[algorithm].block_size).padder()
            padded_data = padder.update(data)
            padded_data += padder.finalize()
            ct = encryptor.update(padded_data) + encryptor.finalize()
        else:
            ct = encryptor.update(data) + encryptor.finalize()
        return ct, encryptor, iv

    def decryptor(self, algorithm, mode, key, data, iv=None, decryptor=None, block_size=None, last=True):
        if decryptor:
            data = decryptor.update(data)
            if mode == 1 and last:
                if block_size is None:
                    block_size = algorithms_options[algorithm].block_size
                unpadder = padding.PKCS7(block_size).unpadder()
                data = unpadder.update(data)
                data = data + unpadder.finalize()
            return data, decryptor
        else:
            cipher = Cipher(algorithms_options[algorithm](
                key), cipher_modes_options[mode](iv))
            decryptor = cipher.decryptor()
            data = decryptor.update(data)
            if mode == 1 and last:
                if block_size is None:
                    block_size = algorithms_options[algorithm].block_size
                unpadder = padding.PKCS7(block_size).unpadder()
                data = unpadder.update(data)
                data = data + unpadder.finalize()
            return data, decryptor

    def dh_digest_key(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        req = requests.get(f'{SERVER_URL}/api/digest_key', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.DIGEST_KEY = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',).derive(shared_key)

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/digest_key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            quit()

    def dh_message_key(self):
        private_key = ec.generate_private_key(ec.SECP384R1())

        req = requests.get(f'{SERVER_URL}/api/key', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.MESSAGE_KEY = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',).derive(shared_key)

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            quit()

    def digest(self, key, hash, data):
        h = hmac.HMAC(key, hashes_options[hash]())
        h.update(data)
        return h.finalize()

    def simple_digest(self, hash, data):
        digest = hashes.Hash(hashes_options[hash]())
        digest.update(data)
        return digest.finalize()

    def verify_digest(self, key, hash, data, digest):
        h = hmac.HMAC(key, hashes_options[hash]())
        h.update(data)
        try:
            h.verify(digest)
            return True
        except InvalidSignature:
            return False


if __name__ == '__main__':
    c = Client()
    c.main()

