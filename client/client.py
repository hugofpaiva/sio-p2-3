import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding

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
        MESSAGE_KEY = None
        DIGEST_KEY = None
        selected_algorithm = None
        selected_hash = None
        selected_mode = None


    def main(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")
        
        # Choosing options
        #Algorithm Option
        #0. AES
        #1. Camellia
        #2. ChaCha20
        print("Generating Algorithms Options...")
        algs = []
        num_opt_alg = random.randint(1, len(algorithms_options))
        for i in range(0, num_opt_alg):
            rand = random.randint(0,len(algorithms_options)-1)
            while rand in algs:
                rand = random.randint(0,len(algorithms_options)-1)    
            algs.append(rand)
        
        #Hash Option
        #0 SHA3_256
        #1 SHA3_512
        #2 SHA256
        #3 SHA512
        print("Generating Hash Options...")
        hashes = []
        num_opt_hash = random.randint(1, len(hashes_options))
        for i in range(0, num_opt_hash):
            rand = random.randint(0,len(hashes_options)-1)
            while rand in hashes:
                rand = random.randint(0,len(hashes_options)-1)    
            hashes.append(rand)

        #Cipher Mode
        #0.CTR
        #1.CBC
        #2.OFB
        #3.CFB
        print("Generating Cipher Mode Options...")
        modes = []
        num_opt_modes = random.randint(1, len(cipher_modes_options))
        for i in range(0, num_opt_modes):
            rand = random.randint(0,len(cipher_modes_options)-1)
            while rand in modes:
                rand = random.randint(0,len(cipher_modes_options)-1)    
            modes.append(rand)



        available_options = {'algorithms': algs, 'hashes': hashes, 'modes': modes}

        print("\nContacting Server")

        req = requests.post(f'{SERVER_URL}/api/protocols', data=json.dumps(available_options).encode('latin'), headers={"content-type": "application/json"})

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
                options, decryptor_var = self.decryptor(self.selected_algorithm,self.selected_mode, self.MESSAGE_KEY, options, iv)
            
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
            proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

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
                data, decryptor_var = self.decryptor(self.selected_algorithm,self.selected_mode, self.MESSAGE_KEY, data, decryptor=decryptor_var)
            else:
                data, decryptor_var = self.decryptor(self.selected_algorithm,self.selected_mode, self.MESSAGE_KEY, data, iv)     

            data = binascii.a2b_base64(data)

            try:
                
                proc.stdin.write(data)
            except:
                break

            if chunk_id % 5 == 0:
                self.dh_digest_key()
                self.dh_message_key()
            else:
                self.MESSAGE_KEY = self.simple_digest(self.selected_hash, self.MESSAGE_KEY)
                self.DIGEST_KEY = self.simple_digest(self.selected_hash, self.DIGEST_KEY)

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
            cipher = Cipher(algorithms_options[algorithm](key), cipher_modes_options[mode](iv))
            encryptor = cipher.encryptor()
            if mode == 1:
                padder = padding.PKCS7(algorithms_options[algorithm].block_size).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
                ct = encryptor.update(padded_data) + encryptor.finalize()
            else:
                ct = encryptor.update(data) + encryptor.finalize()
            return ct, encryptor, iv

    def decryptor(self, algorithm, mode, key, data, iv=None, decryptor = None, block_size=None, last = True):
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
            cipher = Cipher(algorithms_options[algorithm](key), cipher_modes_options[mode](iv))
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

            server_public_key = binascii.a2b_base64(response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.DIGEST_KEY = HKDF(
                algorithm=hashes_options[self.selected_hash](),
                length=32, #256 bits consoante o algoritmo
                salt=None, #osrandom
                info=b'handshake data',).derive(shared_key)


        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/digest_key', data=json.dumps(response).encode('latin'), headers={"content-type": "application/json"})

        if req.status_code != 200:
            quit()

    def dh_message_key(self):
        private_key = ec.generate_private_key(ec.SECP384R1())

        req = requests.get(f'{SERVER_URL}/api/key')
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            self.MESSAGE_KEY = HKDF(
                algorithm=hashes_options[self.selected_hash](),
                length=32, #256 bits consoante o algoritmo
                salt=None, #osrandom
                info=b'handshake data',).derive(shared_key)


        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(serialized_public).decode('latin').strip()}

        req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(response).encode('latin'), headers={"content-type": "application/json"})

        if req.status_code != 200:
            quit()



    def digest(self, key, hash, data):
        h = hmac.HMAC(key, hashes_options[hash]()) #. The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
        h.update(data)
        return h.finalize()

    def simple_digest(self, hash, data):
        digest = hashes.Hash(hashes_options[hash]())
        digest.update(data)
        return digest.finalize()

    def verify_digest(self, key, hash, data, digest):
        h = hmac.HMAC(key, hashes_options[hash]()) #. The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
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
