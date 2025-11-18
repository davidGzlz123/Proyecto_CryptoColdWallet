# El `checksum` es SHA256(pubkey_bytes || ciphertext_bytes) en hexadecimal.

import json
import os
import base64
import hashlib

# Importamos las partes específicas de 'cryptography' (para llaves Ed25519)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key
)
from cryptography.hazmat.backends import default_backend

# Importamos módulos argon2_wrapper y aead_gcm
from app.argon_2_wrapper import generate_key_from_passphrase, create_random_salt, Argon2Settings
from app.aead_gcm import encrypt as aead_encrypt, decrypt as aead_decrypt, EncryptedData

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


# Funciones de Criptografía de Llaves Ed25519

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


# Encripta la llave privada (en formato PEM) con la passphrase
def encrypt_private_key(private_pem, passphrase):
    # Generamos un "salt" aleatorio (16 bytes)
    # El salt es para que la misma passphrase genere llaves diferentes
    # Usamos nuestro helper de Argon2
    salt = create_random_salt(16)
    
    # Usamos los settings por defecto de nuestro módulo Argon2
    settings = Argon2Settings()

    # Derivamos la llave de encriptación 
    key = generate_key_from_passphrase(passphrase, salt, settings)

    # Usamos el cifrador AES-GCM para encriptar la llave privada
    # 'aead_encrypt' ya maneja el nonce y la separación del tag
    encrypted_payload = aead_encrypt(key, private_pem)

    # Creamos el diccionario "crypto" para el JSON
    crypto = {
        'kdf': {
            'name': 'argon2id', # Usamos el nombre correcto
            'salt': b64u(salt), # Guardamos el salt en base64
            'time_cost': settings.time_cost,
            'memory_cost': settings.memory_cost,
            'parallelism': settings.parallelism
        },
        'cipher': 'aes-256-gcm',
        'cipherparams': {
            'nonce': b64u(encrypted_payload.nonce) # Guardamos el nonce en base64
        },
        'ciphertext': b64u(encrypted_payload.ciphertext), # Guardamos en base64
        'tag': b64u(encrypted_payload.tag) # Guardamos en base64
    }
    return crypto


# Desencripta la llave privada usando el diccionario 'crypto' y la passphrase
def decrypt_private_key(crypto, passphrase):
    # Revisamos que el KDF (algoritmo de derivación de llave) sea el que soportamos
    if crypto.get('kdf', {}).get('name') != 'argon2id':
        raise ValueError('KDF no soportado (solo argon2id)')

    # Sacamos los datos del diccionario y decodificamos de base64
    salt = b64u_decode(crypto['kdf']['salt'])
    # Leemos los parámetros de Argon2
    settings = Argon2Settings(
        time_cost=int(crypto['kdf']['time_cost']),
        memory_cost=int(crypto['kdf']['memory_cost']),
        parallelism=int(crypto['kdf']['parallelism'])
    )
    nonce = b64u_decode(crypto['cipherparams']['nonce'])
    ciphertext = b64u_decode(crypto['ciphertext'])
    tag = b64u_decode(crypto['tag'])

    # Derivamos la llave de encriptación usando la passphrase y el salt
    key = generate_key_from_passphrase(passphrase, salt, settings)

    # Preparamos la estructura de datos para nuestro módulo AEAD 
    encrypted_data = EncryptedData(ciphertext=ciphertext, nonce=nonce, tag=tag)

    try:
        # Intentamos desencriptar 
        # 'aead_decrypt' ya maneja la 'InvalidTag' y lanza ValueError
        # Si la passphrase es incorrecta, esto debería fallar
        priv_pem = aead_decrypt(key, encrypted_data)
        return priv_pem
    except ValueError:
        # Si falla, es seguro que el passphrase esté mal o el keystore esté corrupto
        raise ValueError('ERROR: Passphrase incorrecto o el keystore esta corrupto.')


# Funciones del Keystore JSON

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
    # Encriptamos la llave privada (Ahora usa Argon2 y nuestro AEAD)
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
        # (Este es el mensaje de error mejorado de P1)
        raise ValueError('ERROR: Checksum invalido. El archivo parece estar corrupto.')

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
            # (Este es el mensaje de error mejorado de P1)
            raise ValueError('ERROR FATAL: Inconsistencia de llaves. Keystore invalido.')
    except Exception as e:
        # Si falla al cargar la llave PEM, algo salió muy mal
        raise ValueError('Clave privada inválida después de desencriptar.')

    # Si todo salió bien, devolvemos la llave privada (PEM) y la pública (raw)
    return priv_pem, pubkey_raw


# Cambia la passphrase del keystore (re-encripta la clave privada)
def change_keystore_passphrase(path, old_passphrase, new_passphrase):
    """
    Cambia la passphrase de un keystore existente.

    Pasos:
    1. Carga el keystore desde 'path'.
    2. Deriva la llave antigua con old_passphrase y desencripta la private key.
    3. Valida la nueva passphrase (no vacía, longitud mínima).
    4. Genera un nuevo salt, deriva una nueva llave con Argon2 y re-encripta.
    5. Actualiza campos 'kdf.salt', 'cipherparams.nonce', 'ciphertext', 'tag' y 'checksum'.
    6. Guarda el keystore de vuelta en 'path'.
    """
    if not new_passphrase:
        raise ValueError("La nueva passphrase no puede estar vacía.")

    if len(new_passphrase) < 8:
        raise ValueError("La nueva passphrase debe tener al menos 8 caracteres.")

    # 1. Cargar keystore
    keystore = load_keystore(path)

    crypto = keystore['crypto']
    kdf_info = crypto['kdf']
    cipherparams = crypto['cipherparams']

    # 2. Reconstruir parámetros de Argon2 para la llave antigua
    if kdf_info.get('name') != 'argon2id':
        raise ValueError("KDF no soportado para cambio de passphrase (se espera argon2id).")

    salt_old = b64u_decode(kdf_info['salt'])
    settings_old = Argon2Settings(
        time_cost=int(kdf_info['time_cost']),
        memory_cost=int(kdf_info['memory_cost']),
        parallelism=int(kdf_info['parallelism'])
    )

    key_old = generate_key_from_passphrase(old_passphrase, salt_old, settings_old)

    # 3. Decodificar datos cifrados actuales
    nonce_old = b64u_decode(cipherparams['nonce'])
    ciphertext_old = b64u_decode(crypto['ciphertext'])
    tag_old = b64u_decode(crypto['tag'])

    encrypted_data_old = EncryptedData(
        ciphertext=ciphertext_old,
        nonce=nonce_old,
        tag=tag_old
    )

    # 4. Desencriptar la llave privada con la passphrase antigua
    try:
        priv_pem = aead_decrypt(key_old, encrypted_data_old)
    except ValueError:
        # Passphrase vieja incorrecta o datos corruptos
        raise ValueError("Passphrase antigua incorrecta o keystore corrupto.")

    # 5. Generar un nuevo salt y nueva llave para la passphrase nueva
    new_salt = create_random_salt(16)
    settings_new = Argon2Settings(
        time_cost=settings_old.time_cost,
        memory_cost=settings_old.memory_cost,
        parallelism=settings_old.parallelism
    )
    key_new = generate_key_from_passphrase(new_passphrase, new_salt, settings_new)

    # 6. Re-encriptar la llave privada con la nueva llave
    encrypted_new = aead_encrypt(key_new, priv_pem)

    # 7. Actualizar campos del keystore (kdf, cipherparams, ciphertext, tag)
    kdf_info['salt'] = b64u(new_salt)
    kdf_info['time_cost'] = settings_new.time_cost
    kdf_info['memory_cost'] = settings_new.memory_cost
    kdf_info['parallelism'] = settings_new.parallelism

    cipherparams['nonce'] = b64u(encrypted_new.nonce)
    crypto['ciphertext'] = b64u(encrypted_new.ciphertext)
    crypto['tag'] = b64u(encrypted_new.tag)

    # 8. Recalcular el checksum con el nuevo ciphertext
    pubkey_raw = b64u_decode(keystore['pubkey'])
    ciphertext_bytes_new = b64u_decode(crypto['ciphertext'])
    keystore['checksum']['value'] = compute_checksum(pubkey_raw, ciphertext_bytes_new)

    # 9. Guardar keystore modificado
    save_keystore(path, keystore)

    return keystore
