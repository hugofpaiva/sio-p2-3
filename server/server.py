from twisted.web import server, resource
from twisted.internet import reactor

import logging
import binascii
import json
import os
import math
import base64

from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
from cryptography.x509.oid import NameOID

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

ALGORITHMS_OPTIONS = [algorithms.AES, algorithms.Camellia]
HASHES_OPTIONS = [hashes.SHA256, hashes.SHA3_256]
CIPHER_MODES_OPTIONS = [modes.CTR, modes.OFB, modes.CFB]

CLIENT_INFO = {}

SERVER_CERT = None

CC_CERTS = {}
ROOT_CERTS = {}
CRLS = []


def load_cert(path):
    ''' Leitura de certificados X.509 '''
    with open(path, 'rb') as f:
        cert_data = f.read()
        try:
            return x509.load_pem_x509_certificate(cert_data)
        except:
            return x509.load_der_x509_certificate(cert_data)


def load_crl(path):
    ''' Leitura de CRL X.509 '''
    with open(path, 'rb') as f:
        crl_data = f.read()
        try:
            return x509.load_der_x509_crl(crl_data)
        except:
            return x509.load_pem_x509_crl(crl_data)


def get_chain():
    ''' Obtenção de certificados para futura construção da cadeias de certificados para autenticar o cliente '''
    for root, dirs, files in os.walk("../cc_certs/"):
        for filename in files:
            if filename != '.DS_Store':
                certificate = load_cert("../cc_certs/" + filename)
                if verify_date(certificate):
                    CC_CERTS[certificate.subject] = certificate

    for root, dirs, files in os.walk("../root_certs/"):
        for filename in files:
            if filename != '.DS_Store':
                certificate = load_cert("../root_certs/" + filename)
                if verify_date(certificate):
                    ROOT_CERTS[certificate.subject] = certificate


def get_crls():
    ''' Obtenção de crls para futura  autenticação do cliente '''
    for root, dirs, files in os.walk("../cc_crl/"):
        for filename in files:
            if filename != '.DS_Store':
                CRLS.append(load_crl("../cc_crl/" + filename))


def get_cc_chain(cert, chain={}):
    ''' Construção da cadeia de certificados de um dado certificado proveniente do cartão de cidadão '''
    chain[cert.subject] = cert

    if cert.issuer == cert.subject and cert.issuer in ROOT_CERTS:
        return chain
    elif cert.issuer in ROOT_CERTS:
        return get_cc_chain(ROOT_CERTS[cert.issuer], chain)
    elif cert.issuer in CC_CERTS:
        return get_cc_chain(CC_CERTS[cert.issuer], chain)

    return False


def full_chain_cert_verify(chain, cert, first=False):
    ''' Verificação da validade do certificado do cliente de acordo com a data, propósito e assinatura, repetindo o processo para todos os certificados da sua cadeia '''
    issuer_cert = chain[cert.issuer]
    if verify_date(cert) and verify_purpose(cert, first) and verify_crls(cert) and verify_signatures(cert, issuer_cert):
        if cert.issuer == issuer_cert.issuer:
            return True
        else:
            return full_chain_cert_verify(chain, issuer_cert)
    else:
        print('\033[31m'+"Can't verify certificate integrity"+'\033[0m')
        return False


def verify_crls(cert):
    ''' Verificação da validade do certificado de acordo com as crls carregadas '''
    for crl in CRLS:
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
            return False
    return True


def verify_purpose(cert, is_cc=False):
    ''' Verificação do propósito de um certificado (varia consoante o tipo) '''
    if is_cc:
        if cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            return True
    else:
        if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return True
    return False


def verify_signatures(cert, issuer_cert):
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


def verify_date(cert):
    ''' Verificação da validade da data de um certificado '''
    if datetime.now() > cert.not_valid_after:
        return False
    else:
        return True


def sign(bytes):
    ''' Assinatura de bytes com a private key do servidor '''
    with open("../server_certs/server-localhost_pk.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)

    signature = private_key.sign(
        bytes,
        asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric.padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def decrypt_catalog():
    ''' Obtenção das músicas decriptadas para variáveis (memória RAM) '''
    private_key = None
    file_name = None
    decrypted_key = None
    iv = None

    try:

        with open("../server_certs/server-localhost_pk.pem", "rb") as server_cert_file:
            private_key = serialization.load_pem_private_key(
                server_cert_file.read(), None)

        info_file = open('file_info.txt', 'rb')

        for line in info_file.readlines():
            file_name = line[0:128-line[127]].decode('utf-8')
            encrypted_key = line[128:384]
            iv = line[384:416]

            decrypted_key = private_key.decrypt(
                encrypted_key,
                asymmetric.padding.OAEP(
                    mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            for root, dirs, files in os.walk("./encrypted_catalog/"):
                for filename in files:
                    if filename != '.DS_Store':
                        if filename.split('.')[0] == file_name.split('.')[0]:

                            block_size = algorithms.AES.block_size // 8

                            with open("./encrypted_catalog/" + filename, mode='rb') as encrypted_song_file:
                                counter = 0
                                content = encrypted_song_file.read(block_size)

                                cipher = Cipher(algorithms.AES(
                                    decrypted_key), modes.OFB(iv))
                                decryptor = cipher.decryptor()

                                SONGS[file_name] = bytearray()

                                while True:
                                    if len(content) < block_size:
                                        SONGS[file_name] += bytearray(
                                            decryptor.update(content) + decryptor.finalize())
                                        break
                                    else:
                                        SONGS[file_name] += bytearray(
                                            decryptor.update(content))

                                    counter += 1
                                    encrypted_song_file.seek(counter*block_size)
                                    content = encrypted_song_file.read(block_size)
    except:
        print('\033[31m'+"Error loading encrypted songs"+'\033[0m')
        quit()

    return 


def license_check(media_id, user_id):
    ''' Verificação da validade das licenças de obtenção de músicas para uma dada música e cliente, retornando True caso o cliente tenha pelo menos uma licença válida '''
    has_access = False
    for root, dirs, files in os.walk("./licenses/"):
        for filename in files:
            filename_split = filename.split("_")
            # Verificação inicial com o nome do ficheiro
            if filename_split[1] == media_id and CLIENT_INFO[user_id]['serial_number_cc'] == filename_split[0] and datetime.strptime(filename_split[2].split(".")[0], "%Y-%m-%d-%H-%M-%S") > datetime.now():
                with open("./licenses/"+filename, "rb") as f:
                    content = f.read()
                    content = content.split(b"-")
                    license = base64.b64decode(content[0])
                    signature = base64.b64decode(content[1])
                    try:
                        # Verificação da assinatura
                        SERVER_CERT.public_key().verify(
                            signature,
                            license,
                            asymmetric.padding.PSS(
                                mgf=asymmetric.padding.MGF1(
                                    hashes.SHA256()),
                                salt_length=asymmetric.padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )

                        license = json.loads(license.decode('latin'))
                        # Verificação da própria licença
                        if license['media_id'] == media_id and CLIENT_INFO[user_id]['serial_number_cc'] == license['serial_number_cc'] and datetime.strptime(license['date_of_expiration'], "%Y-%m-%d-%H-%M-%S") > datetime.now():
                            has_access = True
                            return has_access
                    except InvalidSignature:
                        pass
    return has_access

def encryptor(algorithm, mode, key, data, encryptor=None, iv=None, last=True):
    ''' Cifra de dados de acordo com o protocolo escolhido '''
    if encryptor:
        ct = encryptor.update(data)
        if last:
            ct += encryptor.finalize()
        return ct, encryptor, iv
    else:
        iv = os.urandom(ALGORITHMS_OPTIONS[algorithm].block_size // 8)
        cipher = Cipher(ALGORITHMS_OPTIONS[algorithm](
            key), CIPHER_MODES_OPTIONS[mode](iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data)
        if last:
            ct += encryptor.finalize()
        return ct, encryptor, iv

def decryptor(algorithm, mode, key, data, iv=None, decryptor=None):
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

def generate_digest(key, hash, data):
    ''' Geração de digest para verificação de integridade com recurso a HMAC '''
    h = hmac.HMAC(key, HASHES_OPTIONS[hash]())
    h.update(data)
    return h.finalize()

def generate_simple_digest(hash, data):
    ''' Geração de um digest simples '''
    digest = hashes.Hash(HASHES_OPTIONS[hash]())
    digest.update(data)
    return digest.finalize()

def verify_digest(key, hash, data, digest):
    ''' Verificação da integridade com recurso a HMAC e ao digest gerado previamente '''
    h = hmac.HMAC(key, HASHES_OPTIONS[hash]())
    h.update(data)
    try:
        h.verify(digest)
        return True
    except InvalidSignature:
        return False


class MediaServer(resource.Resource):
    isLeaf = True

    def get_auth(self, request):
        ''' Envio do certificado do servidor '''
        id = request.getHeader('Authorization')
        certificate = binascii.b2a_base64(
            SERVER_CERT.public_bytes(Encoding.PEM))

        certificate, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                           ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], certificate)

        certificate_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                         CLIENT_INFO[id]['options']['selected_hash'], certificate)

        response = {'certificate': certificate.decode(
            'latin'), 'digest': certificate_digest.decode('latin'), 'iv': iv.decode('latin')}
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_auth(self, request):
        ''' Receção de uma nounce para posterior envio permitindo a autenticação do servidor '''
        id = request.getHeader('Authorization')
        response = json.loads(request.content.read())
        digest = response['digest'].encode('latin')
        nounce = response['nounce'].encode('latin')
        iv = response['iv'].encode('latin')

        if verify_digest(CLIENT_INFO[id]['digest_key'], CLIENT_INFO[id]['options']['selected_hash'], nounce, digest):
            nounce, decryptor_var = decryptor(
                CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], nounce, iv)

            nounce = binascii.a2b_base64(nounce)

            signed_nounce = binascii.b2a_base64(sign(nounce))

            signed_nounce, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                                    ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], signed_nounce)

            signed_nounce_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                                CLIENT_INFO[id]['options']['selected_hash'], signed_nounce)

            response = {'signed_nounce': signed_nounce.decode(
                'latin'), 'digest': signed_nounce_digest.decode('latin'), 'iv': iv.decode('latin')}

            request.setResponseCode(200)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps(response).encode('latin')
        
        print('\033[31m'+f"Data integrity of communication violated for user {id}"+'\033[0m')
        request.setResponseCode(401)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    def get_cc_auth(self, request):
        ''' Envio de nounce para posterior autenticação do cliente '''
        id = request.getHeader('Authorization')
        nounce = os.urandom(32)

        CLIENT_INFO[id]['cc_nounce'] = nounce

        nounce = binascii.b2a_base64(nounce)

        nounce, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                      ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], nounce)

        nounce_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                    CLIENT_INFO[id]['options']['selected_hash'], nounce)

        response = {'nounce': nounce.decode('latin'), 'digest': nounce_digest.decode(
            'latin'), 'iv': iv.decode('latin')}

        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps(response).encode('latin')

    def post_cc_auth(self, request):
        ''' Receção de nounce e certificado para autenticar cliente '''
        responseCode = 401
        response = json.loads(request.content.read())
        id = request.getHeader('Authorization')
        certificate_digest = response['certificate_digest'].encode('latin')
        certificate = response['certificate'].encode('latin')
        certificate_iv = response['certificate_iv'].encode('latin')
        signed_nounce_digest = response['signed_nounce_digest'].encode('latin')
        signed_nounce = response['signed_nounce'].encode('latin')
        signed_nounce_iv = response['signed_nounce_iv'].encode('latin')

        if verify_digest(CLIENT_INFO[id]['digest_key'], CLIENT_INFO[id]['options']['selected_hash'], certificate, certificate_digest):
            certificate, decryptor_var = decryptor(
                CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], certificate, certificate_iv)
        else:
            print('\033[31m'+f"Data integrity of communication violated for user {id}"+'\033[0m')
            request.setResponseCode(responseCode)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

        if verify_digest(CLIENT_INFO[id]['digest_key'], CLIENT_INFO[id]['options']['selected_hash'], signed_nounce, signed_nounce_digest):
            signed_nounce, decryptor_var = decryptor(
                CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], signed_nounce, signed_nounce_iv)
        else:
            print('\033[31m'+f"Data integrity of communication violated for user {id}"+'\033[0m')
            request.setResponseCode(responseCode)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

        certificate = binascii.a2b_base64(certificate)

        signed_nounce = binascii.a2b_base64(signed_nounce)

        client_cert = x509.load_pem_x509_certificate(certificate)

        chain = get_cc_chain(client_cert)

        nounce = CLIENT_INFO[id]['cc_nounce']

        if chain and nounce:
            if full_chain_cert_verify(chain, client_cert, True):
                try:
                    client_cert.public_key().verify(
                        signed_nounce,
                        nounce,
                        asymmetric.padding.PKCS1v15(),
                        hashes.SHA1()
                    )
                    responseCode = 200
                    CLIENT_INFO[id]['serial_number_cc'] = client_cert.subject.get_attributes_for_oid(
                        NameOID.SERIAL_NUMBER)[0].value
                except InvalidSignature:
                    print('\033[31m'+"Invalid signed nounce"+'\033[0m')
                    pass

        request.setResponseCode(responseCode)
        request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
        return b''

    def get_key(self, request):
        ''' Envio de chave pública do servidor para Diffie Hellman '''
        private_key = ec.generate_private_key(ec.SECP384R1())

        id = request.getHeader('Authorization')

        if request.path == b'/api/digest_key' and CLIENT_INFO[id]['dh_digest_private_key']:
            CLIENT_INFO[id]['dh_digest_private_key'] = private_key
        elif request.path == b'/api/key' and CLIENT_INFO[id]['dh_private_key']:
            CLIENT_INFO[id]['dh_private_key'] = private_key
        else:
            request.setResponseCode(401)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

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
        ''' Receção de chave pública do cliente para Diffie Hellman '''
        response = json.loads(request.content.read())

        client_public_key = binascii.a2b_base64(
            response['key'].encode('latin'))

        loaded_public_key = serialization.load_pem_public_key(
            client_public_key,)

        id = request.getHeader('Authorization')

        shared_key = None

        if request.path == b'/api/digest_key' and CLIENT_INFO[id]['dh_digest_private_key']:
            shared_key = CLIENT_INFO[id]['dh_digest_private_key'].exchange(
                ec.ECDH(), loaded_public_key)
        elif request.path == b'/api/key' and CLIENT_INFO[id]['dh_private_key']:
            shared_key = CLIENT_INFO[id]['dh_private_key'].exchange(
                ec.ECDH(), loaded_public_key)
        else:
            request.setResponseCode(401)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

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
        ''' Receção dos protocolos para a cifra '''
        response = json.loads(request.content.read())

        selected_algorithm = random.choice(response['algorithms'])
        selected_hash = random.choice(response['hashes'])
        selected_mode = random.choice(response['modes'])

        id = request.getHeader('Authorization')

        CLIENT_INFO[id] = {}
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
        ''' Envio dos protocolos para a cifra '''
        id = request.getHeader('Authorization')

        options = json.dumps(
            CLIENT_INFO[id]['options']).encode('latin')

        options, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                       ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], options)

        options_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                     CLIENT_INFO[id]['options']['selected_hash'], options)

        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'options': options.decode('latin'), 'digest': options_digest.decode('latin'), 'iv': iv.decode('latin')}).encode('latin')

    def get_license(self, request):
        ''' Geração e envio de uma licença para uuma dada música e utilizador com validade de 1 hora '''
        id = request.getHeader('Authorization')
        media_id = request.args.get(b'id', [None])[0].decode('latin')

        date = datetime.now() + timedelta(hours=1)
        new_license = {'serial_number_cc': CLIENT_INFO[id]['serial_number_cc'],
                       'media_id': media_id,
                       'date_of_expiration': date.strftime("%Y-%m-%d-%H-%M-%S")
                       }

        new_license = json.dumps(new_license).encode('latin')

        signature = sign(new_license)

        result = base64.b64encode(new_license) + \
            b"-" + base64.b64encode(signature)

        with open("./licenses/"+str(CLIENT_INFO[id]['serial_number_cc'])+"_"+str(media_id)+"_"+str(date.strftime("%Y-%m-%d-%H-%M-%S"))+".txt", "wb") as f:
            f.write(result)
            f.close()

        result, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                      ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], result)

        result_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                    CLIENT_INFO[id]['options']['selected_hash'], result)

        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'license': result.decode('latin'), 'digest': result_digest.decode('latin'), 'iv': iv.decode('latin')}).encode('latin')

    def do_list(self, request):
        ''' Envio da lista de músicas para um dado utilizador com a respetiva permissão para ouvir '''

        id = request.getHeader('Authorization')

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            has_access = license_check(media_id, id)

            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration'],
                'has_access': has_access
            })

        response = {'media_list': media_list}

        response = json.dumps(response).encode('latin')

        response, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                        ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], response)

        response_digest = generate_digest(CLIENT_INFO[id]['digest_key'],
                                      CLIENT_INFO[id]['options']['selected_hash'], response)

        request.responseHeaders.addRawHeader(
            b"content-type", b"application/json")
        return json.dumps({'media_list': response.decode('latin'), 'digest': response_digest.decode('latin'), 'iv': iv.decode('latin')}).encode('latin')

    def do_download(self, request):
        ''' Envio de um determinado chunk de uma música caso o utilizador tenha licença '''
        id = request.getHeader('Authorization')
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

        # Check license
        if not license_check(media_id, id):
            request.setResponseCode(401)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'License not found'}).encode('latin')

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

        if chunk_id == 0:
            CLIENT_INFO[id]['encryptor'] = None

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')

        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk

        if SONGS[media_item['file_name']]:

            data = SONGS[media_item['file_name']][offset:offset+CHUNK_SIZE]

            data = binascii.b2a_base64(data)

            encryptor_cypher = CLIENT_INFO[id]['encryptor']

            data, encryptor_cypher, iv = encryptor(CLIENT_INFO[id]['options']['selected_algorithm'], CLIENT_INFO[id]
                                                        ['options']['selected_mode'], CLIENT_INFO[id]['message_key'], data, encryptor_cypher, last=chunk_id == totalchunks)

            digest_data = generate_digest(CLIENT_INFO[id]['digest_key'],
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

            # Double Ratchet
            if chunk_id % 5 != 0 or chunk_id == 0:
                CLIENT_INFO[id]['message_key'] = generate_simple_digest(
                    CLIENT_INFO[id]['options']['selected_hash'], CLIENT_INFO[id]['message_key'])
                CLIENT_INFO[id]['digest_key'] = generate_simple_digest(
                    CLIENT_INFO[id]['options']['selected_hash'], CLIENT_INFO[id]['digest_key'])

            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps(
                response, indent=4
            ).encode('latin')

        else:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(
                b"content-type", b"application/json")
            return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def logout(self, request):
        ''' Término de sessão de um utilizador, eliminando os seus dados (exceto licenças) '''
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

            elif request.path == b'/api/get_music':
                return self.get_license(request)

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
                return b'GET Methods: /api/protocols /api/list /api/download /api/key /api/digest_key /api/logout /api/get_music /api/auth /api/cc_auth'

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
                return b'POST Methods: /api/protocols /api/key /api/digest_key /api/auth /api/cc_auth'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(
                b"content-type", b"text/plain")
            return b''

print("Running initial tasks")

SERVER_CERT = load_cert('../server_certs/server-localhost.crt')
get_chain()
get_crls()
decrypt_catalog()

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
