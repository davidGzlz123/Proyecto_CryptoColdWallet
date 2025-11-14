# El `checksum` es SHA256(pubkey_bytes || ciphertext_bytes) en hexadecimal.
# Requisitos: instalar la librería `cryptography` (pip install cryptography).

import json
import os
import base64
import hashlib

# Importamos las partes específicas de 'cryptography'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption, load_pem_private_key
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# --- Funciones para Base64 ---

# Función para codificar bytes a string base64 URL-safe (sin padding '=')
def b64u(data_bytes):
    # Codifica a base64 URL-safe
    encoded = base64.urlsafe_b64encode(data_bytes)
    # Quita el padding '=' del final y lo convierte a string
    return encoded.rstrip(b"=").decode('ascii')


# Función para decodificar string base64
def b64u_decode(data_str):
    # El base64  a veces no tiene padding al final.
    # Python necesita ese padding para decodificar.
    # Esta fórmula agrega los '=' que falten.
    missing_padding = len(data_str) % 4
    if missing_padding != 0:
        data_str += '=' * (4 - missing_padding)
    
    return base64.urlsafe_b64decode(data_str)


# --- Funciones de Criptografía ---

# Genera un par de llaves Ed25519
def generate_ed25519_keypair():
    # Creamos la llave privada
    priv = Ed25519PrivateKey.generate()
    
    # La pasamos a formato PEM (un string de texto)
    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Sacamos la llave pública
    pub = priv.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    
    # Devolvemos las dos llaves
    return priv_pem, pub


# Deriva una llave de 32 bytes usando la passphrase y un salt
def derive_key(passphrase, salt, iterations=200000, length=32):
    # Usamos el algoritmo PBKDF2 con SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length, # Longitud de la llave que queremos (32 bytes = 256 bits)
        salt=salt,
        iterations=iterations,
        backend=default_backend() # Usamos el backend por defecto de cryptography
    )
    # Generamos la llave desde la passphrase
    # Hay que pasar la passphrase a bytes
    return kdf.derive(passphrase.encode('utf-8'))


# Encripta la llave privada (en formato PEM) con la passphrase
def encrypt_private_key(private_pem, passphrase):
    # Generamos un "salt" aleatorio (16 bytes)
    # El salt es para que la misma passphrase genere llaves diferentes
    salt = os.urandom(16)
    iters = 200000 # Mismo número de iteraciones que en derive_key

    # Derivamos la llave de encriptación
    key = derive_key(passphrase, salt, iterations=iters)

    # Usamos el cifrador AES-GCM
    aesgcm = AESGCM(key)

    # 4. Generamos un nonce aleatorio de 12 bytes
    nonce = os.urandom(12)

    # Encriptamos la llave privada
    ct_con_tag = aesgcm.encrypt(nonce, private_pem, None)

    # La librería cryptography pega el tag de autenticación al final del ciphertext.
    # El tag de AES-GCM es siempre de 16 bytes.
    # Tenemos que separarlos para guardarlos como dice el formato.
    tag = ct_con_tag[-16:]
    ciphertext = ct_con_tag[:-16]

    # Creamos el diccionario "crypto" para el JSON
    crypto = {
        'kdf': {
            'name': 'pbkdf2',
            'salt': b64u(salt), # Guardamos el salt en base64
            'iters': iters,
            'hash': 'sha256'
        },
        'cipher': 'aes-256-gcm',
        'cipherparams': {
            'nonce': b64u(nonce) # Guardamos el nonce en base64
        },
        'ciphertext': b64u(ciphertext), # Guardamos en base64
        'tag': b64u(tag) # Guardamos en base64
    }
    return crypto


# Desencripta la llave privada usando el diccionario 'crypto' y la passphrase
def decrypt_private_key(crypto, passphrase):
    # Revisamos que el KDF (algoritmo de derivación de llave) sea el que soportamos
    if crypto.get('kdf', {}).get('name') != 'pbkdf2':
        raise ValueError('KDF no soportado')

    # Sacamos los datos del diccionario y decodificamos de base64
    salt = b64u_decode(crypto['kdf']['salt'])
    iters = int(crypto['kdf']['iters'])
    nonce = b64u_decode(crypto['cipherparams']['nonce'])
    ciphertext = b64u_decode(crypto['ciphertext'])
    tag = b64u_decode(crypto['tag'])

    # Derivamos la llave (tiene que dar la misma que al encriptar)
    key = derive_key(passphrase, salt, iterations=iters)

    # Preparamos el cifrador AES-GCM
    aesgcm = AESGCM(key)

    # Volvemos a juntar el ciphertext y el tag, como los da la librería
    ct_con_tag = ciphertext + tag

    try:
        # Intentamos desencriptar
        # Si la passphrase es incorrecta, esto deberíafallar
        priv_pem = aesgcm.decrypt(nonce, ct_con_tag, None)
        return priv_pem
    except Exception as e:
        # Si falla, lo más seguro es que la passphrase esté mal
        raise ValueError('Desencriptado fallido. Passphrase incorrecta o datos corruptos.')


# --- Funciones del Keystore ---

# Calcula el checksum (sha256) de la llave pública y el ciphertext
def compute_checksum(pubkey_bytes, ciphertext_bytes):
    # Creamos un objeto hash
    h = hashlib.sha256()
    # Le pasamos la llave pública
    h.update(pubkey_bytes)
    # Le pasamos el ciphertext
    h.update(ciphertext_bytes)
    # Pedimos el resultado en hexadecimal pero como string
    return h.hexdigest()


# Crea el diccionario completo del keystore
def make_keystore(private_pem, pubkey_raw, passphrase):
    # Encriptamos la llave privada
    crypto = encrypt_private_key(private_pem, passphrase)

    # Calculamos el checksum
    # Necesitamos el ciphertext en bytes no en base64 para el hash
    ciphertext_bytes = b64u_decode(crypto['ciphertext'])
    checksum = compute_checksum(pubkey_raw, ciphertext_bytes)

    # Armamos el diccionario final
    keystore = {
        'version': 1,
        'pubkey': b64u(pubkey_raw), # Llave pública en base64
        'crypto': crypto, # El diccionario de encriptación
        'checksum': {'alg': 'sha256', 'value': checksum}
    }
    return keystore


# Guarda el keystore en un archivo JSON
def save_keystore(path, keystore):
    # 'w' es para escribir (write)
    # 'encoding='utf-8'' es para que guarde bien acentos y caracteres raros
    with open(path, 'w', encoding='utf-8') as f:
        # json.dump escribe el diccionario 'keystore' en el archivo 'f'
        # indent=2 hace que el JSON se vea bonito y ordenado
        json.dump(keystore, f, indent=2, ensure_ascii=False)


# Carga el keystore (un diccionario) desde un archivo JSON
def load_keystore(path):
    # 'r' es para leer (read)
    with open(path, 'r', encoding='utf-8') as f:
        # json.load lee el archivo 'f' y lo convierte a diccionario de Python
        data = json.load(f)

    # Validamos que el JSON tenga las partes principales.
    # Si no, no es un keystore válido.
    if 'version' not in data or 'crypto' not in data or 'pubkey' not in data or 'checksum' not in data:
        raise ValueError('Formato de keystore inválido. Faltan campos.')
    return data


# Desbloquea el keystore.
# Valida el checksum y luego desencripta.
def unlock_keystore(keystore, passphrase):
    # Sacamos los datos que necesitamos del keystore (decodificando de b64)
    pubkey_raw = b64u_decode(keystore['pubkey'])
    crypto = keystore['crypto']
    ciphertext_bytes = b64u_decode(crypto['ciphertext'])

    # Verificar el checksum
    # El checksum es para saber si el archivo se corrompió
    expected_checksum = keystore['checksum']['value']
    actual_checksum = compute_checksum(pubkey_raw, ciphertext_bytes)

    # Comparamos el checksum guardado con el que acabamos de calcular
    if expected_checksum != actual_checksum:
        raise ValueError('Checksum inválido: el archivo está corrupto')

    # Desencriptar
    # Si el checksum está bien, intentamos desencriptar.
    # Esto puede fallar si la passphrase es incorrecta.
    priv_pem = decrypt_private_key(crypto, passphrase)

    # Verificación extra
    # Revisamos que la llave privada que sacamos sí corresponde
    # a la llave pública que está guardada en el JSON.
    try:
        # Cargamos la llave privada (en formato PEM)
        priv = load_pem_private_key(priv_pem, password=None, backend=default_backend())
        # Le pedimos su llave pública (en formato raw)
        pub_from_priv = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        # Comparamos byte por byte
        if pub_from_priv != pubkey_raw:
            # Esto no debería pasar si el checksum y la passphrase están bien
            raise ValueError('Error de consistencia: la llave privada no corresponde con la pública')
    except Exception as e:
        # Si falla al cargar la llave PEM, algo salió muy mal
        raise ValueError('Clave privada inválida después de desencriptar.')

    # Si todo salió bien, devolvemos la llave privada (PEM) y la pública (raw)
    return priv_pem, pubkey_raw