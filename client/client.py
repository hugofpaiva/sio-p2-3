import requests
import logging
import binascii
import json
import os
import subprocess
import sys
import uuid
import base64
import PyKCS11
import random
import time
from datetime import datetime

from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat import primitives
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

ALGORITHMS_OPTIONS = [algorithms.AES, algorithms.Camellia]
HASHES_OPTIONS = [hashes.SHA256, hashes.SHA3_256]
CIPHER_MODES_OPTIONS = [modes.CTR, modes.OFB, modes.CFB]


class Client:
    def __init__(self):
        self.message_key = None
        self.digest_key = None
        self.selected_algorithm = None
        self.selected_hash = None
        self.selected_mode = None
        self.root_ca_cert = self.load_cert('../server_certs/SIO_CA_1.crt')
        self.server_cert = None
        self.session_cc = None 
        self.user_cc = None 
        self.cert_cc = None 
        self.private_key_cc = None 
        self.id = uuid.uuid4().hex 

    def load_cert(self, path):
        ''' Leitura de certificados X.509 '''
        with open(path, 'rb') as f:
            data = f.read()
            return x509.load_pem_x509_certificate(data)

    def full_cert_verify(self, cert, issuer_cert):
        ''' Verificação da validade do certificado do servidor de acordo com a data, propósito e assinatura, dando o ceritficado da entidade emissora (Root CA) '''
        if cert.issuer == issuer_cert.issuer:
            if self.verify_date(cert) and self.verify_purpose(cert) and self.verify_signatures(cert, issuer_cert):
                return True
            else:
                print('\033[31m'+"Can't verify certificate integrity"+'\033[0m')
        else:
            print('\033[31m'+"Can't chain to Root CA"+'\033[0m')
        return False

    def verify_purpose(self, cert):
        ''' Verificação do propósito do certificado do servidor '''
        if ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return True
        else:
            return False

    def verify_signatures(self, cert, issuer_cert):
        ''' Verificação da assinatura de um certificado, dando o ceritficado da entidade emissora '''
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
        ''' Verificação da validade da data de um certificado '''
        if datetime.now() > cert.not_valid_after:
            return False
        else:
            return True

    def get_cc(self):
        ''' Verificação da presença do cartão de cidadão e carregamento de informação necessária ao programa '''
        try:
            # Localização para Linux
            lib = '/usr/local/lib/libpteidpkcs11.so'

            # Localização para MacOs
            if sys.platform.startswith('darwin'):
                lib = '/usr/local/lib/libpteidpkcs11.dylib'
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib)

            # Listar o primeiro slot com um token
            slot = pkcs11.getSlotList(tokenPresent=True)[0]

        except:
            print('\033[31m'+"Citizen card not present"+'\033[0m')
            quit()

        # Filtrar atributos
        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]

        self.session_cc = pkcs11.openSession(slot)

        try:
            for obj in self.session_cc.findObjects():
                attr = self.session_cc.getAttributeValue(obj, all_attr)
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

                # Obtenção do certificado de autenticação
                if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                    if attr['CKA_CERTIFICATE_TYPE'] != None:
                        self.cert_cc = x509.load_der_x509_certificate(
                            bytes(attr['CKA_VALUE']))
                        # Número do cartão de cidadão
                        self.user_cc = self.cert_cc.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[
                            0].value

            self.private_key_cc = self.session_cc.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
        except:
            print('\033[31m'+"Invalid Citizen card"+'\033[0m')
            quit()

        print("Correct reading of the Citizen Card\n")
        return

    def main(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        self.get_cc()

        # Escolha de opções

        # Opções de algoritmos de cifra
        # 0. AES
        # 1. Camellia
        print("Generating Algorithms Options...")
        algs = []
        num_opt_alg = random.randint(1, len(ALGORITHMS_OPTIONS))
        for i in range(0, num_opt_alg):
            rand = random.randint(0, len(ALGORITHMS_OPTIONS)-1)
            while rand in algs:
                rand = random.randint(0, len(ALGORITHMS_OPTIONS)-1)
            algs.append(rand)

        # Opções de hash
        # 0. SHA256
        # 1. SHA3_256
        print("Generating Hash Options...")
        hashes = []
        num_opt_hash = random.randint(1, len(HASHES_OPTIONS))
        for i in range(0, num_opt_hash):
            rand = random.randint(0, len(HASHES_OPTIONS)-1)
            while rand in hashes:
                rand = random.randint(0, len(HASHES_OPTIONS)-1)
            hashes.append(rand)

        # Opções de modo de cifra
        # 0.CTR
        # 1.OFB
        # 2.CFB
        print("Generating Cipher Mode Options...")
        modes = []
        num_opt_modes = random.randint(1, len(CIPHER_MODES_OPTIONS))
        for i in range(0, num_opt_modes):
            rand = random.randint(0, len(CIPHER_MODES_OPTIONS)-1)
            while rand in modes:
                rand = random.randint(0, len(CIPHER_MODES_OPTIONS)-1)
            modes.append(rand)

        available_options = {'algorithms': algs,
                             'hashes': hashes, 'modes': modes}

        print("\nContacting Server\n")

        print("Sending all Cipher related options")

        # Envio das opções relativas à cifra
        req = requests.post(f'{SERVER_URL}/api/protocols', data=json.dumps(
            available_options).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            print('\033[31m'+"Error sending Cipher related options"+'\033[0m')
            quit()
        else:
            response = req.json()
            self.selected_algorithm = response['selected_algorithm']
            self.selected_hash = response['selected_hash']
            self.selected_mode = response['selected_mode']

        # DH Exchange
        print("Exchanging Symmetric Keys for communication using DH")
        self.dh_message_key()

        # DH Digest Key Exchange
        print("Exchanging Symmetric Keys for communication digests using DH")
        self.dh_digest_key()

        # Verificação da opções relativas à cifra
        req = requests.get(f'{SERVER_URL}/api/protocols', headers={"Authorization": self.id})
        if req.status_code != 200:
            print('\033[31m'+"Error getting Cipher related options"+'\033[0m')
            quit()
        else:
            response = req.json()
            digest = response['digest'].encode('latin')
            options = response['options'].encode('latin')
            iv = response['iv'].encode('latin')

            if self.verify_digest(self.digest_key, self.selected_hash, options, digest):
                options, decryptor_var = self.decryptor(
                    self.selected_algorithm, self.selected_mode, self.message_key, options, iv)

                options = json.loads(options.decode('latin'))
                if(self.selected_algorithm != options['selected_algorithm'] or self.selected_hash != options['selected_hash'] or self.selected_mode != options['selected_mode']):
                    print('\033[31m'+"Cipher related options different from the server"+'\033[0m')
                    quit()
                else:
                    print('\033[1m'+"Protocol integrity verified"+'\033[0m')
            else:
                print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                quit()


        # Verificação da autenticidade do servidor
        req = requests.get(f'{SERVER_URL}/api/auth', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()
            digest = response['digest'].encode('latin')
            certificate = response['certificate'].encode('latin')
            iv = response['iv'].encode('latin')

            if self.verify_digest(self.digest_key, self.selected_hash, certificate, digest):
                certificate, decryptor_var = self.decryptor(
                    self.selected_algorithm, self.selected_mode, self.message_key, certificate, iv)
            else:
                print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                quit()

            certificate = binascii.a2b_base64(certificate)
            self.server_cert = x509.load_pem_x509_certificate(certificate)

            if not self.full_cert_verify(self.server_cert, self.root_ca_cert):
                print('\033[31m'+"Could not validate server certificate"+'\033[0m')
                quit()

            server_nounce = os.urandom(32)

            nounce = binascii.b2a_base64(server_nounce)

            nounce, encryptor_cypher, iv = self.encryptor(self.selected_algorithm, self.selected_mode, self.message_key, nounce)

            nounce_digest = self.digest(self.digest_key,
                                     self.selected_hash, nounce)

            response = {'nounce': nounce.decode('latin'), 'digest': nounce_digest.decode('latin'), 'iv': iv.decode('latin')}

            req = requests.post(f'{SERVER_URL}/api/auth', data=json.dumps(
                response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

            if req.status_code == 200:
                response = req.json()
                digest = response['digest'].encode('latin')
                signed_nounce = response['signed_nounce'].encode('latin')
                iv = response['iv'].encode('latin')

                if self.verify_digest(self.digest_key, self.selected_hash, signed_nounce, digest):
                    signed_nounce, decryptor_var = self.decryptor(
                        self.selected_algorithm, self.selected_mode, self.message_key, signed_nounce, iv)
                else:      
                    print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                    quit()

                signed_nounce = binascii.a2b_base64(signed_nounce)

                try:
                    self.server_cert.public_key().verify(
                        signed_nounce,
                        server_nounce,
                        asymmetric.padding.PSS(
                            mgf=asymmetric.padding.MGF1(
                                primitives.hashes.SHA256()),
                            salt_length=asymmetric.padding.PSS.MAX_LENGTH
                        ),
                        primitives.hashes.SHA256()
                    )
                    print('\033[1m'+"Authenticated server"+'\033[0m')
                except InvalidSignature:
                    print('\033[31m'+"Server could not be authenticated"+'\033[0m')
                    quit()

            else:
                print('\033[31m'+"Error getting signed nounce for server autentication"+'\033[0m')
                quit()

        else:
            print('\033[31m'+"Error getting server certificate"+'\033[0m')
            quit()
    
        # Autenticação do Utilizador
        req = requests.get(f'{SERVER_URL}/api/cc_auth', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()
            digest = response['digest'].encode('latin')
            nounce = response['nounce'].encode('latin')
            iv = response['iv'].encode('latin')

            if self.verify_digest(self.digest_key, self.selected_hash, nounce, digest):
                nounce, decryptor_var = self.decryptor(
                    self.selected_algorithm, self.selected_mode, self.message_key, nounce, iv)
            else:
                print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                quit()

            nounce = binascii.a2b_base64(nounce)

            try:
                mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

                signed_nounce = bytes(self.session_cc.sign(
                    self.private_key_cc, nounce, mechanism))
            except:
                print('\033[31m'+"Unable to sign with citizen card"+'\033[0m')
                quit()
        else:
            print('\033[31m'+"Error getting nounce for user autentication"+'\033[0m')
            quit()

        certificate = binascii.b2a_base64(self.cert_cc.public_bytes(Encoding.PEM))
        signed_nounce = binascii.b2a_base64(signed_nounce)
        
        certificate, encryptor_cypher, certificate_iv = self.encryptor(self.selected_algorithm, self.selected_mode, self.message_key, certificate)

        certificate_digest = self.digest(self.digest_key,
                                     self.selected_hash, certificate)

        signed_nounce, encryptor_cypher, signed_nounce_iv = self.encryptor(self.selected_algorithm, self.selected_mode, self.message_key, signed_nounce)

        signed_nounce_digest = self.digest(self.digest_key,
                                     self.selected_hash, signed_nounce)

        response = {'certificate': certificate.decode('latin'), 'certificate_digest': certificate_digest.decode('latin'), 'certificate_iv': certificate_iv.decode('latin'),
         'signed_nounce': signed_nounce.decode('latin'), 'signed_nounce_digest': signed_nounce_digest.decode('latin'), 'signed_nounce_iv': signed_nounce_iv.decode('latin')}

        req = requests.post(f'{SERVER_URL}/api/cc_auth', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code == 200:
            print('\033[1m'+"Authenticated user"+'\033[0m')
        else:
            print('\033[31m'+"Server failed to authenticate user"+'\033[0m')
            quit()

        # Obter lista de músicas
        while True:
            media_list = None
            while True:
                req = requests.get(f'{SERVER_URL}/api/list', headers={"Authorization": self.id})
                if req.status_code == 200:
                    print("Got Server List")
                else:
                    print('\033[31m'+"Error getting server list"+'\033[0m')
                    continue

                response = req.json()
                digest = response['digest'].encode('latin')
                media_list = response['media_list'].encode('latin')
                iv = response['iv'].encode('latin')

                if self.verify_digest(self.digest_key, self.selected_hash, media_list, digest):
                    media_list, decryptor_var = self.decryptor(
                    self.selected_algorithm, self.selected_mode, self.message_key, media_list, iv)

                    media_list = json.loads(media_list.decode('latin'))['media_list']
                else:
                    print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                    quit()

                # Present a simple selection menu
                idx = 0
                print("\nMEDIA CATALOG")
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
                
                # Obter licença para música
                if not media_list[selection]['has_access']:
                    req = requests.get(f'{SERVER_URL}/api/get_music?id={media_list[selection]["id"]}', headers={"Authorization": self.id})
                    if req.status_code == 200:
                        print()
                        print('\033[1m'+f"Access granted to the song \'{media_list[selection]['name']}\' for 1 hour"+'\033[0m')
                        print()
                        response = req.json()
                        digest = response['digest'].encode('latin')
                        license = response['license'].encode('latin')
                        iv = response['iv'].encode('latin')

                        if self.verify_digest(self.digest_key, self.selected_hash, license, digest):
                            license, decryptor_var = self.decryptor(
                                self.selected_algorithm, self.selected_mode, self.message_key, license, iv)
                            decoded_license = license.split(b"-")
                            decoded_license = base64.b64decode(decoded_license[0])
                            decoded_license = json.loads(decoded_license.decode('latin'))
                            with open("./licenses/"+str(decoded_license['serial_number_cc'])+"_"+str(decoded_license['media_id'])+"_"+str(decoded_license['date_of_expiration'])+".txt", "wb") as f:
                                f.write(license)
                                f.close()
                        else:
                            print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                            quit()
                            
                    else:
                        print('\033[31m'+"Error getting song license"+'\033[0m')
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
            kill_needed = True

            # Get data from server and send it to the ffplay stdin through a pipe
            for chunk_id in range(media_item['chunks']):
                req = requests.get(
                    f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk_id}', headers={"Authorization": self.id})
                if req.status_code != 200:
                    print('\033[31m'+"Error getting chunk of song"+'\033[0m')
                    quit()
                chunk = req.json()

                if chunk_id == 0:
                    iv = chunk['iv'].encode('latin')

                digest = chunk['digest'].encode('latin')

                data = chunk['data'].encode('latin')

                if not self.verify_digest(self.digest_key, self.selected_hash, data, digest):
                    print('\033[31m'+"Data integrity of communication violated"+'\033[0m')
                    quit()

                if decryptor_var:
                    data, decryptor_var = self.decryptor(
                        self.selected_algorithm, self.selected_mode, self.message_key, data, decryptor=decryptor_var)
                else:
                    data, decryptor_var = self.decryptor(
                        self.selected_algorithm, self.selected_mode, self.message_key, data, iv)

                data = binascii.a2b_base64(data)

                if chunk_id % 5 == 0:
                    self.dh_digest_key()
                    self.dh_message_key()
                else:
                    self.message_key = self.simple_digest(
                        self.selected_hash, self.message_key)
                    self.digest_key = self.simple_digest(
                        self.selected_hash, self.digest_key)

                try:
                    proc.stdin.write(data)
                except:
                    kill_needed = False
                    break
            if kill_needed:
                time.sleep(5)
                proc.kill()

                

    def encryptor(self, algorithm, mode, key, data):
        ''' Cifra de dados de acordo com o protocolo escolhido '''
        iv = os.urandom(ALGORITHMS_OPTIONS[algorithm].block_size // 8)
        cipher = Cipher(ALGORITHMS_OPTIONS[algorithm](
            key), CIPHER_MODES_OPTIONS[mode](iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct, encryptor, iv

    def decryptor(self, algorithm, mode, key, data, iv=None, decryptor=None):
        ''' Decifra de dados de acordo com o protocolo escolhido '''
        if decryptor:
            data = decryptor.update(data)
            return data, decryptor
        else:
            cipher = Cipher(ALGORITHMS_OPTIONS[algorithm](
                key), CIPHER_MODES_OPTIONS[mode](iv))
            decryptor = cipher.decryptor()
            data = decryptor.update(data)
            return data, decryptor

    def dh_digest_key(self):
        ''' Troca de novas chaves simétricas para utilização ao criar digests nas comunicações '''
        private_key = ec.generate_private_key(ec.SECP384R1())
        req = requests.get(f'{SERVER_URL}/api/digest_key', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.digest_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',).derive(shared_key)
        else:
            print('\033[31m'+"Error trading DH symmetric keys for communication digests"+'\033[0m')
            quit()

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/digest_key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            print('\033[31m'+"Error trading DH symmetric keys for communication digests"+'\033[0m')
            quit()

    def dh_message_key(self):
        ''' Troca de novas chaves simétricas para cifrar as comunicações '''
        private_key = ec.generate_private_key(ec.SECP384R1())

        req = requests.get(f'{SERVER_URL}/api/key', headers={"Authorization": self.id})
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(
                response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(
                server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.message_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',).derive(shared_key)
        else:
            print('\033[31m'+"Error trading DH symmetric keys for communication"+'\033[0m')
            quit()

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(
            response).encode('latin'), headers={"content-type": "application/json", "Authorization": self.id})

        if req.status_code != 200:
            print('\033[31m'+"Error trading DH symmetric keys for communication"+'\033[0m')
            quit()

    def digest(self, key, hash, data):
        ''' Geração de digest para verificação de integridade com recurso a HMAC '''
        h = hmac.HMAC(key, HASHES_OPTIONS[hash]())
        h.update(data)
        return h.finalize()

    def simple_digest(self, hash, data):
        ''' Geração de um digest simples '''
        digest = hashes.Hash(HASHES_OPTIONS[hash]())
        digest.update(data)
        return digest.finalize()

    def verify_digest(self, key, hash, data, digest):
        ''' Verificação da integridade com recurso a HMAC e ao digest gerado previamente '''
        h = hmac.HMAC(key, HASHES_OPTIONS[hash]())
        h.update(data)
        try:
            h.verify(digest)
            return True
        except InvalidSignature:
            return False


if __name__ == '__main__':
    c = Client()
    c.main()

