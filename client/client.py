import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import PyKCS11
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
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
        #
        self.cadeia_cert0 = None
        self.session = None
        self.private_key = None
        self.user_cc = None
        self.cc_cert = None

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

    def get_cc(self):
        # Verificar cc 
        try:
            lib = '/usr/local/lib/libpteidpkcs11.so'

            if sys.platform.startswith('darwin'):
                lib = '/usr/local/lib/libpteidpkcs11.dylib'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)
            slot_list = pkcs11.getSlotList()
    
            #Agora que está tudo numa função esta condição parece-me desnecessária
            #if len(slots) != 0:
               # slot_list = slots


    
        except:
            print("ERRO VERIFY_CC")
            quit()
        
        #for slot in slots:
            #pass
            #print(pkcs11.getTokenInfo(slot))
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
    
        all_attr = []
        for elem in PyKCS11.CKA.keys():
            if isinstance(elem, int):
                all_attr.append(elem)
    
        cadeia_certs = []
    
        session = pkcs11.openSession(slot)
    
        cur_user = None
    
        for obj in session.findObjects():
            attr = session.getAttributeValue(obj, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            if attr['CKA_CERTIFICATE_TYPE'] != None:
                cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))
                cadeia_certs.append(x509.load_der_x509_certificate(bytes(attr['CKA_VALUE'])))
                if cur_user == None:
                    cur_user = cert.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)[0].value + " " + cert.subject.get_attributes_for_oid(NameOID.SURNAME)[0].value + " " + cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
                    self.user_cc = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        #print("\nCADEIA_CERT")
        #for c in cadeia_cert:
            #print("\n", c, c.not_valid_before, c.not_valid_after)
            #print("Valido ? ", validate_date(c.not_valid_before, c.not_valid_after))
        #print("\nUSER", user)
    
        private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
        #print("\nPRIVATE", private_key)
        #print("\nPUBLIC", cert.public_key())
    
        #print("\ncadeia_cert[0]: ", cadeia_cert[0])
        #print("\nSession: ", session)
        #print("\nPrivateKey ", private_key)
        #print("\nUser: ", cur_user)

        self.cadeia_cert0 = cadeia_certs[0]
        self.session = session
        self.private_key = private_key
        self.user_cc = cur_user
        self.cc_cert = cert

        return cadeia_certs[0]


    #_____________________________

    def main(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        self.verify_cc()

        # Getting server certificate
        req = requests.get(f'{SERVER_URL}/api/auth')
        if req.status_code == 200:
            response = req.json()
            certificate = binascii.a2b_base64(
                response['certificate'].encode('latin'))
            self.server_cert = x509.load_pem_x509_certificate(certificate)

            if not self.full_cert_verify(self.server_cert, self.root_ca_cert):
                quit()

        else:
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
            available_options).encode('latin'), headers={"content-type": "application/json"})

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

        req = requests.get(f'{SERVER_URL}/api/protocols')
        if req.status_code != 200:
            quit()
        else:
            response = req.json()
            digest = response['digest'].encode('latin')
            options = response['options'].encode('latin')
            iv = response['iv'].encode('latin')
            print(options)

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
        req = requests.get(f'{SERVER_URL}/api/list')
        if req.status_code == 200:
            print("Got Server List")

        media_list = req.json()

        # Present a simple selection menu
        idx = 0
        print("MEDIA CATALOG\n")
        for item in media_list:
            print(f'{idx} - {media_list[idx]["name"]}')
        print("----")

        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                sys.exit(0)

            if not selection.isdigit():
                continue

            selection = int(selection)
            if 0 <= selection < len(media_list):
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
                f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk_id}')
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

        req = requests.get(f'{SERVER_URL}/api/logout')
        if req.status_code == 200:
            print("All done!")

    def encryptor(self, algorithm, mode, key, data, encryptor=None, block_size=None):
        if encryptor:
            if mode == 1:
                padder = padding.PKCS7(block_size).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
                ct = encryptor.update(data) + encryptor.finalize()
            else:
                ct = encryptor.update(data) + encryptor.finalize()
            return ct, encryptor
        else:
            # TODO Generate through secret module, also verify if all algorithms used are 128bits to generate only 16 bytes
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
        req = requests.get(f'{SERVER_URL}/api/digest_key')
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.DIGEST_KEY = HKDF(
                algorithm=hashes_options[self.selected_hash](),
                length=32,  # 256 bits consoante o algoritmo
                salt=None,  # osrandom
                info=b'handshake data',).derive(shared_key)

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/digest_key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json"})

        if req.status_code != 200:
            quit()

    def dh_message_key(self):
        private_key = ec.generate_private_key(ec.SECP384R1())

        req = requests.get(f'{SERVER_URL}/api/key')
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.MESSAGE_KEY = HKDF(
                algorithm=hashes_options[self.selected_hash](),
                length=32,  # 256 bits consoante o algoritmo
                salt=None,  # osrandom
                info=b'handshake data',).derive(shared_key)

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json"})

        if req.status_code != 200:
            quit()

    def digest(self, key, hash, data):
        # . The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
        h = hmac.HMAC(key, hashes_options[hash]())
        h.update(data)
        return h.finalize()

    def simple_digest(self, hash, data):
        digest = hashes.Hash(hashes_options[hash]())
        digest.update(data)
        return digest.finalize()

    def verify_digest(self, key, hash, data, digest):
        # . The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
        h = hmac.HMAC(key, hashes_options[hash]())
        h.update(data)
        try:
            h.verify(digest)
            return True
        except InvalidSignature:
            return False


if __name__ == '__main__':
    c = Client()
    while True:
        c.main()
        time.sleep(1)
