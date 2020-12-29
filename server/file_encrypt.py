from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

f = open("../server_certs/server-localhost_pk.pem", "rb")
private_key = serialization.load_pem_private_key(f.read(), None)

public_key = private_key.public_key()

f_info = open("file_info.txt", "ab")

for root, dirs, files in os.walk("./catalog/"):
    for filename in files:
        if filename != '.DS_Store':
            block_size = algorithms.AES.block_size // 8
            iv = os.urandom(block_size)

            key = os.urandom(32)

            cipher = Cipher(algorithms.AES(
                key), modes.OFB(iv))
            encryptor = cipher.encryptor()

            f = open("./catalog/" + filename, "rb")
            f2 = open("./encrypted_catalog/" + filename.split(".")[0] + ".bin", "wb")
            counter=0
            content = f.read(block_size)

            while True:
                if len(content) < block_size:
                    ct = encryptor.update(content) + encryptor.finalize()
                    break
                else:
                    ct = encryptor.update(content)

                f2.write(ct)

                counter+=1
                f.seek(counter*block_size)
                content = f.read(block_size)

            f.close()
            f2.close()                 

            encrypted_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            f_info.write(bytes(filename, encoding='utf8')+b"-"+encrypted_key+b"-"+iv)
f_info.close

