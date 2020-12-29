#!/usr/bin/env python

from base64 import decode
from requests.models import Response
from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import binascii
import json
import os
import math
import base64
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography import x509
from datetime import datetime
import PyKCS11
from cryptography.x509.oid import ExtendedKeyUsageOID

import random

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = {'898a08080d1840793122b7e118b27a95d117ebce':
           {
               'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
               'album': 'Upbeat Ukulele Background Music',
               'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
               'duration': 3*60+33,
               'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
               'file_size': 3407202
           }
           }

SONGS = {}

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

algorithms_options = [algorithms.AES, algorithms.Camellia]
hashes_options = [hashes.SHA256, hashes.SHA3_256]
cipher_modes_options = [modes.CTR, modes.CBC, modes.OFB, modes.CFB]

CLIENT_INFO = {}

server_cert = None

cc_certs = {}
root_certs = {}

crl= []


def load_cert(path):
    with open(path, 'rb') as f:
        cert_data = f.read()
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except:
            return x509.load_der_x509_certificate(cert_data)

def load_crl(path):
    with open(path, 'rb') as f:
        crl_data = f.read()
        try:
            return x509.load_der_x509_crl(crl_data)
        except:
            return x509.load_pem_x509_crl(crl_data)


def get_chain():
    for root, dirs, files in os.walk("../cc_certs/"):
        for filename in files:
            if filename != '.DS_Store':
                certificate = load_cert("../cc_certs/" + filename)
                if verify_date(certificate):
                    cc_certs[certificate.subject] = certificate

    for root, dirs, files in os.walk("../root_certs/"):
        for filename in files:
            if filename != '.DS_Store':
                certificate = load_cert("../root_certs/" + filename)
                if verify_date(certificate):
                    root_certs[certificate.subject] = certificate

def get_crl():
    for root, dirs, files in os.walk("../cc_crl/"):
        for filename in files:
            if filename != '.DS_Store':
                crl.append(load_crl("../cc_crl/" + filename))              


def get_cc_chain(cert, chain={}):
    chain[cert.subject] = cert

    if cert.issuer == cert.subject and cert.issuer in root_certs:
        return chain
    elif cert.issuer in root_certs:
        return get_cc_chain(root_certs[cert.issuer], chain)
    elif cert.issuer in cc_certs:
        return get_cc_chain(cc_certs[cert.issuer], chain)

    # Trust Chain isn't complete
    return False


def full_chain_cert_verify(chain, cert, first=False):
    issuer_cert = chain[cert.issuer]
    if verify_date(cert) and verify_purpose(cert, first) and verify_crl(cert) and verify_signatures(cert, issuer_cert):
        if cert.issuer == issuer_cert.issuer:
            print("Reached valid root CA")
            return True
        else:
            return full_chain_cert_verify(chain, issuer_cert)
    else:
        print("Can't verify certificate integraty")
        print("Chain Broken")
        return False

def verify_crl(cert):
    for list in crl:
        if list.get_revoked_certificate_by_serial_number(cert.serial_number):
            return False
    return True


def verify_purpose(cert, is_cc=False):
    if is_cc:
        if cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            return True
        else:
            return False
    else:
        if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return True
            else:
                return False
        else:
            return False


def verify_signatures(cert, issuer_cert):
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


def verify_date(cert):
    if datetime.now() > cert.not_valid_after:
        return False
    else:
        return True


def sign(nounce):
    with open("../server_certs/server-localhost_pk.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)

    signature = private_key.sign(
        nounce,
        asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric.padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def decrypt_uiid(id):
    #Get server private key 
    with open("../server_certs/server-localhost_pk.pem", "rb") as server_cert_file:
        private_key = serialization.load_pem_private_key(server_cert_file.read(), None)

        return private_key.decrypt(
            id,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

def decrypt_catalog(os_walk_path):

    private_key = None
    file_name = None
    decrypted_key = None 
    iv = None

    #Get server private key 
    with open("../server_certs/server-localhost_pk.pem", "rb") as server_cert_file:
        private_key = serialization.load_pem_private_key(server_cert_file.read(), None)

    #Open info file
    info_file = open('file_info.txt', 'rb')

    #For each line
    for line in info_file.readlines():
        #Get info
        file_name = line[0:128-line[127]].decode('utf-8')
        encrypted_key = line[128:384]
        iv = line[384:416]

        #Decrypt key
        decrypted_key = private_key.decrypt(
            encrypted_key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Go through encrypted song directory
        for root, dirs, files in os.walk(os_walk_path):
            for filename in files:
                if filename.split('.')[0] == file_name.split('.')[0]:
                    
                    block_size = algorithms.AES.block_size // 8
                    #Open song file for current key 
                    with open(os_walk_path + filename, mode='rb') as encrypted_song_file:
                        counter=0
                        content = encrypted_song_file.read(block_size)

                        cipher = Cipher(algorithms.AES(decrypted_key), modes.OFB(iv))
                        decryptor = cipher.decryptor()

                        SONGS[file_name] = bytearray()
                        
                        while True:
                            if len(content) < block_size:
                                SONGS[file_name] += bytearray(decryptor.update(content) + decryptor.finalize())
                                break
                            else:
                                SONGS[file_name] += bytearray(decryptor.update(content))

                            counter+=1
                            encrypted_song_file.seek(counter*block_size)
                            content = encrypted_song_file.read(block_size)

    return True
                    



class MediaServer(resource.Resource):
    isLeaf = True

    def encryptor(self, algorithm, mode, key, data, encryptor=None, iv=None, last=True):
        if encryptor:
            if mode == 1 and last:
                padder = padding.PKCS7(CHUNK_SIZE // 8).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
                ct = encryptor.update(data)
            else:
                ct = encryptor.update(data)
            if last:
                ct += encryptor.finalize()
            return ct, encryptor, iv
        else:
            iv = os.urandom(algorithms_options[algorithm].block_size // 8)
            cipher = Cipher(algorithms_options[algorithm](
                key), cipher_modes_options[mode](iv))
            encryptor = cipher.encryptor()
            if mode == 1 and len(data) < algorithms_options[algorithm].block_size:
                padder = padding.PKCS7(
                    algorithms_options[algorithm].block_size).padder()
                padded_data = padder.update(data)
                padded_data += padder.finalize()
                ct = encryptor.update(padded_data)
            else:
                ct = encryptor.update(data)
            if last:
                ct += encryptor.finalize()
            return ct, encryptor, iv

    def decryptor(self, algorithm, mode, key, data, iv=None, decryptor=None, block_size=None, last=False):
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

    def get_auth(self, request):
        response = {'certificate': binascii.b2a_base64(
            server_cert.public_bytes(Encoding.PEM)).decode('latin')}
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_auth(self, request):
        response = json.loads(request.content.read())

        nounce = binascii.a2b_base64(
            response['nounce'].encode('latin'))

        nounce = sign(nounce)

        response = {'signed_nounce': binascii.b2a_base64(
            nounce).decode('latin')}

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def get_cc_auth(self, request):
        id = request.getHeader('Authorization')
        nounce = os.urandom(32)

        CLIENT_INFO[id] = {}
        CLIENT_INFO[id]['cc_nounce'] = nounce

        response = {'nounce': binascii.b2a_base64(
            nounce).decode('latin').strip()}

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_cc_auth(self, request):
        response = json.loads(request.content.read())

        id = request.getHeader('Authorization')
        
        certificate = binascii.a2b_base64(
            response['certificate'].encode('latin'))

        signed_nounce = binascii.a2b_base64(
            response['signed_nounce'].encode('latin'))

        client_cert = x509.load_pem_x509_certificate(certificate)

        chain = get_cc_chain(client_cert)

        nounce = CLIENT_INFO[id]['cc_nounce']

        responseCode = 401

        if chain:
            if full_chain_cert_verify(chain, client_cert, True):
                try:
                    client_cert.public_key().verify(
                        signed_nounce,
                        nounce,
                        asymmetric.padding.PKCS1v15(),
                        hashes.SHA1()
                    )
                    responseCode = 200
                except InvalidSignature:
                    pass

        request.setResponseCode(responseCode)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    def get_key(self, request):
        private_key = ec.generate_private_key(ec.SECP384R1())

        id = request.getHeader('Authorization')

        if request.path == b'/api/digest_key':
            CLIENT_INFO[id]['dh_digest_private_key'] = private_key
        elif request.path == b'/api/key':
            CLIENT_INFO[id]['dh_private_key'] = private_key

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin')}
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_key(self, request):
        response = json.loads(request.content.read())

        client_public_key = binascii.a2b_base64(
            response['key'].encode('latin'))

        loaded_public_key = serialization.load_pem_public_key(
            client_public_key,)

        id = request.getHeader('Authorization')

        shared_key = None

        if request.path == b'/api/digest_key':
            shared_key = CLIENT_INFO[id]['dh_digest_private_key'].exchange(
                ec.ECDH(), loaded_public_key)
        elif request.path == b'/api/key':
            shared_key = CLIENT_INFO[id]['dh_private_key'].exchange(
                ec.ECDH(), loaded_public_key)

        MESSAGE_KEY = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',).derive(shared_key)

        if request.path == b'/api/digest_key':
            CLIENT_INFO[id]['digest_key'] = MESSAGE_KEY

        elif request.path == b'/api/key':
            CLIENT_INFO[id]['message_key'] = MESSAGE_KEY

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    def do_post_protocols(self, request):
        response = json.loads(request.content.read())

        selected_algorithm = random.choice(response['algorithms'])
        selected_hash = random.choice(response['hashes'])
        selected_mode = random.choice(response['modes'])

        id = request.getHeader('Authorization')

        CLIENT_INFO[id]['options'] = {}
        CLIENT_INFO[id]['options']['selected_algorithm'] = selected_algorithm
        CLIENT_INFO[id]['options']['selected_hash'] = selected_hash
        CLIENT_INFO[id]['options']['selected_mode'] = selected_mode

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(
            {
                'selected_algorithm': selected_algorithm,
                'selected_hash': selected_hash,
                'selected_mode': selected_mode,
            },
        ).encode('latin')

    def do_get_protocols(self, request):
        id = request.getHeader('Authorization')

        options = json.dumps(
            CLIENT_INFO[id]['options']).encode('latin')
        

        options, encryptor_cypher, iv = self.encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                       ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], options)

        options_digest = self.digest(CLIENT_INFO[id]['digest_key'],
                                     CLIENT_INFO[id]['options']['selected_hash'], options)

        # To use later
        CLIENT_INFO[id]['encryptor'] = None

        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'options': options.decode('latin'), 'digest': options_digest.decode('latin'), 'iv': iv.decode('latin')}).encode('latin')

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        # if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
            })

        # Return list to client
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')

    # Send a media chunk to the client

    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')

        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')

        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')

        # Get the media item
        media_item = CATALOG[media_id]

        totalchunks = math.ceil(media_item['file_size'] / CHUNK_SIZE)

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        
        data = SONGS[media_item['file_name']][offset:offset+CHUNK_SIZE]

        data = binascii.b2a_base64(data)

        id = request.getHeader('Authorization')

        encryptor_cypher = CLIENT_INFO[id]['encryptor']

        data, encryptor_cypher, iv = self.encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                    ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], data, encryptor_cypher, last=chunk_id == totalchunks)

        digest_data = self.digest(CLIENT_INFO[id]['digest_key'],
                                    CLIENT_INFO[id]['options']['selected_hash'], data)

        if chunk_id != totalchunks:
            CLIENT_INFO[id]['encryptor'] = encryptor_cypher
        else:
            CLIENT_INFO[id]['encryptor'] = None

        response = {
            'media_id': media_id,
            'chunk': chunk_id,
            'data': data.decode('latin'),
            'digest': digest_data.decode('latin'),
        }

        if chunk_id == 0:
            response['iv'] = iv.decode('latin')

        if chunk_id % 5 != 0 or chunk_id == 0:
            CLIENT_INFO[id]['message_key'] = self.simple_digest(
                CLIENT_INFO[id]['options']['selected_hash'], CLIENT_INFO[id]['message_key'])
            CLIENT_INFO[id]['digest_key'] = self.simple_digest(
                CLIENT_INFO[id]['options']['selected_hash'], CLIENT_INFO[id]['digest_key'])

        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(
            response, indent=4
        ).encode('latin')

    '''
    # File was not open?
    request.responseHeaders.addRawHeader(
        b"content-type", b"application/json")
    return json.dumps({'error': 'unknown'}, indent=4).encode('latin')
    '''

    def logout(self, request):
        id = request.getHeader('Authorization')
        del CLIENT_INFO[id]
        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    # Handle a GET request

    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)

            elif request.path == b'/api/key':
                return self.get_key(request)

            elif request.path == b'/api/digest_key':
                return self.get_key(request)

            elif request.path == b'/api/logout':
                return self.logout(request)

            elif request.path == b'/api/auth':
                return self.get_auth(request)

            elif request.path == b'/api/cc_auth':
                return self.get_cc_auth(request)

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)

            else:
                request.responseHeaders.addRawHeader(
                    b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(
                b"content-type", b"text/plain")
            return b''

    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        try:
            if request.path == b'/api/protocols':
                return self.do_post_protocols(request)

            elif request.path == b'/api/key':
                return self.post_key(request)

            elif request.path == b'/api/digest_key':
                return self.post_key(request)

            elif request.path == b'/api/auth':
                return self.post_auth(request)

            elif request.path == b'/api/cc_auth':
                return self.post_cc_auth(request)

            else:
                request.responseHeaders.addRawHeader(
                    b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/key'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(
                b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:8080")

server_cert = load_cert('../server_certs/server-localhost.crt')
get_chain()
get_crl()
decrypt_catalog("./encrypted_catalog/")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
