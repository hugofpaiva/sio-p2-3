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

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

algorithms_options = [algorithms.AES, algorithms.Camellia]
hashes_options = [hashes.SHA256, hashes.SHA3_256]
cipher_modes_options = [modes.CTR, modes.CBC, modes.OFB, modes.CFB]

CLIENT_INFO = {}


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

    def verify_digest(self, key, hash, data, digest):
        # . The key should be randomly generated bytes and is recommended to be equal in length to the digest_size of the hash function chosen. You must keep the key secret.
        h = hmac.HMAC(key, hashes_options[hash]())
        h.update(data)
        try:
            h.verify(digest)
            return True
        except InvalidSignature:
            return False

    def get_key(self, request):
        private_key = ec.generate_private_key(ec.SECP384R1())

        if request.path == b'/api/digest_key':
            CLIENT_INFO[request.client.host]['dh_digest_private_key'] = private_key
        elif request.path == b'/api/key':
            CLIENT_INFO[request.client.host]['dh_private_key'] = private_key

        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        response = {'key': binascii.b2a_base64(
            serialized_public).decode('latin').strip()}
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_key(self, request):
        response = json.loads(request.content.read())

        client_public_key = binascii.a2b_base64(
            response['key'].encode('latin'))

        loaded_public_key = serialization.load_pem_public_key(
            client_public_key,)

        if request.path == b'/api/digest_key':
            shared_key = CLIENT_INFO[request.client.host]['dh_digest_private_key'].exchange(
                ec.ECDH(), loaded_public_key)
        elif request.path == b'/api/key':
            shared_key = CLIENT_INFO[request.client.host]['dh_private_key'].exchange(
                ec.ECDH(), loaded_public_key)

        MESSAGE_KEY = HKDF(
            algorithm=hashes_options[CLIENT_INFO[request.client.host]
                                     ['options']['selected_hash']](),
            length=32,
            salt=None,
            info=b'handshake data',).derive(shared_key)

        if request.path == b'/api/digest_key':
            CLIENT_INFO[request.client.host]['digest_key'] = MESSAGE_KEY

        elif request.path == b'/api/key':
            CLIENT_INFO[request.client.host]['message_key'] = MESSAGE_KEY

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    def do_post_protocols(self, request):
        response = json.loads(request.content.read())

        selected_algorithm = random.choice(response['algorithms'])
        selected_hash = random.choice(response['hashes'])
        selected_mode = random.choice(response['modes'])

        CLIENT_INFO[request.client.host] = {}
        CLIENT_INFO[request.client.host]['options'] = {}
        CLIENT_INFO[request.client.host]['options']['selected_algorithm'] = selected_algorithm
        CLIENT_INFO[request.client.host]['options']['selected_hash'] = selected_hash
        CLIENT_INFO[request.client.host]['options']['selected_mode'] = selected_mode

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
        options = json.dumps(
            CLIENT_INFO[request.client.host]['options']).encode('latin')

        options_digest = self.digest(CLIENT_INFO[request.client.host]['digest_key'],
                                     CLIENT_INFO[request.client.host]['options']['selected_hash'], options)

        options, encryptor_cypher, iv = self.encryptor(CLIENT_INFO[request.client.host]['options']['selected_algorithm'], CLIENT_INFO[request.client.host]
                                                       ['options']['selected_mode'], CLIENT_INFO[request.client.host]['message_key'], options)

        # To use later
        CLIENT_INFO[request.client.host]['encryptor'] = None

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
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            data = binascii.b2a_base64(data)

            encryptor_cypher = CLIENT_INFO[request.client.host]['encryptor']

            digest_data = self.digest(CLIENT_INFO[request.client.host]['digest_key'],
                                      CLIENT_INFO[request.client.host]['options']['selected_hash'], data)

            data, encryptor_cypher, iv = self.encryptor(CLIENT_INFO[request.client.host]['options']['selected_algorithm'], CLIENT_INFO[request.client.host]
                                                        ['options']['selected_mode'], CLIENT_INFO[request.client.host]['message_key'], data, encryptor_cypher, last=chunk_id == totalchunks)

            if chunk_id != totalchunks:
                CLIENT_INFO[request.client.host]['encryptor'] = encryptor_cypher
            else:
                CLIENT_INFO[request.client.host]['encryptor'] = None

            response = {
                'media_id': media_id,
                'chunk': chunk_id,
                'data': data.decode('latin'),
                'digest': digest_data.decode('latin'),
            }

            if chunk_id == 0:
                response['iv'] = iv.decode('latin')

            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps(
                response, indent=4
            ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def logout(self, request):
        del CLIENT_INFO[request.client.host]
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

            # elif request.uri == '/api/auth':

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

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
