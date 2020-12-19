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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'




def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    MESSAGE_KEY = None
    # Get a list of media files
    print("Contacting Server")

    private_key = ec.generate_private_key(ec.SECP384R1())

    while MESSAGE_KEY is None:
        req = requests.get(f'{SERVER_URL}/api/key')
        if req.status_code == 200:
            response = req.json()

            server_public_key = binascii.a2b_base64(response['key'].encode('latin'))

            loaded_public_key = serialization.load_pem_public_key(server_public_key,)

            shared_key = private_key.exchange(ec.ECDH(), loaded_public_key)

            MESSAGE_KEY = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',).derive(shared_key)

        time.sleep(5)

    public_key = private_key.public_key()

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    response = {'key': binascii.b2a_base64(serialized_public).decode('latin').strip()}

    req = requests.post(f'{SERVER_URL}/api/key', data=json.dumps(response).encode('latin'), headers={"content-type": "application/json"})

    if req.status_code != 200:
        print("deu bosta")
        quit()

    print(MESSAGE_KEY)
    


    # TODO: Secure the session

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


def cipher(algorithm, mode, key, data):
    # depende do modo
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()


if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)
