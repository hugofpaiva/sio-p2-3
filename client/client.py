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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

algorithms_options = [algorithms.AES, algorithms.Camellia, algorithms.ChaCha20]
hashes_options = [hashes.SHA256, hashes.SHA512, hashes.SHA3_256, hashes.SHA3_512]
cipher_modes_options = [modes.CTR, modes.CBC, modes.OFB, modes.CFB]




def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    
    MESSAGE_KEY = None
    # Choosing options
    print("\n|         Algorithms Options         |")
    print("1. AES")
    print("2. Camellia")
    print("3. ChaCha20")
    alg = int(input("Select the number corresponding to the algorithm option: "))

    print("\n|         Hash Options         |")
    print("1. SHA3_256")
    print("2. SHA3_512")
    print("3. SHA256")
    print("4. SHA512")
    hash = int(input("Select the number corresponding to the hash option: "))

    print("\n|         Cipher Mode Options         |")
    print("1. CTR")
    print("2. CBC")
    print("3. OFB")
    print("4. CFB")
    mode = int(input("Select the number corresponding to the cipher mode option: "))

    selected_algorithm = alg-1
    selected_hash = hash-1
    selected_mode = mode-1

    selected_options = {'algorithm': alg-1, 'hash': hash-1, 'mode': mode-1}

    print("Contacting Server")

    req = requests.post(f'{SERVER_URL}/api/protocols', data=json.dumps(selected_options).encode('latin'), headers={"content-type": "application/json"})

    if req.status_code != 200:
        quit()

    # DH Exchange
    private_key = ec.generate_private_key(ec.SECP384R1())

    while MESSAGE_KEY is None:
        req = requests.get(f'{SERVER_URL}/api/key')
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            MESSAGE_KEY = HKDF(
                algorithm=hashes_options[selected_hash](),
                length=32, #256 bits consoante o algoritmo
                salt=None, #osrandom
                info=b'handshake data',).derive(shared_key)

        time.sleep(5)

    public_key = private_key.public_key()

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    response = {'key': binascii.b2a_base64(serialized_public).decode('latin').strip()}

    req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(response).encode('latin'), headers={"content-type": "application/json"})

    if req.status_code != 200:
        quit()

    req = requests.get(f'{SERVER_URL}/api/protocols')
    if req.status_code != 200:
        quit()
    else:
        response = req.json()
        if(selected_algorithm != response['selected_algorithm'] or selected_hash != response['selected_hash'] or selected_mode != response['selected_mode']):
            print("MITM???")
            quit()
        
    
    


    # TODO: Secure the session
    
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

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(
            f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()

        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break


def encryptor(algorithm, mode, key, data, encryptor=None, block_size=0):
    if encryptor:
        if mode == modes.CBC:
            if len(data) < block_size:
                diff=block_size-len(data)
                data+=bytes([diff]*diff) #padding
                ct=encryptor.update(data) + encryptor.finalize()
            else:
                ct = encryptor.update(data)
        else: 
            ct = encryptor.update(data) + encryptor.finalize()
    else:     
        iv = os.urandom(16) #TODO Generate through secret module, also verify if all algorithms used are 128bits to generate only 16 bytes
        if algorithm == 2:
            iv_chacha = os.urandom(16)
            algorithm = algorithms.ChaCha20(key, iv_chacha)
        elif algorithm == 0 or algorithm == 1:
            algorithm = algorithms_options[algorithm](key)
        else:
            print("Incorrect algorithm")
            quit()
        cipher = Cipher(algorithm, cipher_modes_options[mode](iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
    return ct, encryptor

def decryptor(algorithm, mode, key, data):
    iv = os.urandom(16)
    if algorithm == 2:
        iv_chacha = os.urandom(16)
        algorithm = algorithms.ChaCha20(key, iv_chacha)
    elif algorithm == 0 or algorithm == 1:
        algorithm = algorithms_options[algorithm](key)
    cipher = Cipher(algorithm, cipher_modes_options[mode](iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data)

def digest(key, hash, data):
    h = hmac.HMAC(key, hashes_options[hash]) #. The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
    h.update(data)
    return h.finalize()

def verify_digest(key, hash, data):
    h = hmac.HMAC(key, hashes_options[hash]) #. The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
    h.update(data)
    try:
        h.verify()
        return True
    except InvalidSignature:
        return False

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
