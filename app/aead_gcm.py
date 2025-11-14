# app/aead_gcm.py
# Módulo AEAD. Se realiza la implementación de helpers 
# de cifrado AES-256-GCM -> AEAD
# De igual forma, emplea utilidades de Base64.

import os
from base64 import b64encode, b64decode
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Configuración de Criptográficas ---
AES_KEY_SIZE = 32  # 256 bits para AES-256
GCM_NONCE_SIZE = 12 # 96 bits para GCM
GCM_TAG_SIZE = 16  # 128 bits para la etiqueta de autenticación

# Definición de Helpers-B64     

def b64_to_bytes(s: str) -> bytes:
    """Decodificado de un string Base64 (UTF-8) a bytes."""
    return b64decode(s.encode('utf-8'))

def bytes_to_b64(b: bytes) -> str:
    """Codificado de bytes a un string Base64 (UTF-8)."""
    return b64encode(b).decode('utf-8')

# Definición de una Estructura de Datos dedicada al Cifrado 
@dataclass
class EncryptedData:
    """
    Clase enfocada en almacenar a los 3 componentes del 
    cifrado en modo GCM: ciphertext, nonce y el tag.
    """
    ciphertext: bytes
    nonce: bytes
    tag: bytes

    # Función para serializar a bytes Base64
    def to_dict(self) -> dict:
        """
        Conversión de los campos de bytes a Base64 con la idea de
        posteriormente serializar en JSON.
        """
        return {
            "ciphertext_b64": bytes_to_b64(self.ciphertext),
            "nonce_b64": bytes_to_b64(self.nonce),
            "tag_b64": bytes_to_b64(self.tag),
        }
    
    # Función para deserializar desde bytes Base64
    @staticmethod
    def un_dict(data: dict) -> 'EncryptedData':
        """
        Crea un objeto EncryptedData a partir de un dict con strings Base64.
        """
        return EncryptedData(
            ciphertext=b64_to_bytes(data["ciphertext_b64"]),
            nonce=b64_to_bytes(data["nonce_b64"]),
            tag=b64_to_bytes(data["tag_b64"]),
        )

# [Funciones de Cifrado y Descifrado AEAD AES-256-GCM]

# Función de cifrado
def encrypt(key: bytes, plaintext: bytes) -> EncryptedData:

    # 1. Validación de la llave de cifrado 32 bytes
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"La llave debe ser de {AES_KEY_SIZE} bytes.")
    
    # 2. Generación de un nonce aleatorio de 12 bytes
    nonce = os.urandom(GCM_NONCE_SIZE)
    
    # 3. Sección de cifrado en modo AES-GCM
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None) 
    # El tercer parámetro es para datos adicionales autenticados no empleados para este caso.
    
    # 4. Separación del ciphertext y del tag
    ciphertext = ciphertext_and_tag[:-GCM_TAG_SIZE]
    tag = ciphertext_and_tag[-GCM_TAG_SIZE:]
    
    return EncryptedData(ciphertext=ciphertext, nonce=nonce, tag=tag)

# Función de descifrado
def decrypt(key: bytes, encrypted_data: EncryptedData) -> bytes:

    # 1. Validación de la llave de cifrado 32 bytes
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"La llave debe ser de {AES_KEY_SIZE} bytes.")

    # 2. Inicialización del objeto AES-GCM para descifrado
    aesgcm = AESGCM(key)
    
    # 3. Concatenación del ciphertext y el tag 
    ciphertext_and_tag = encrypted_data.ciphertext + encrypted_data.tag
    
    try:
        """ Se busca descifrar y verificar el tag. 
        Si el tag, nonce o la llave son incorrectos, el try fallará.
        """
        plaintext = aesgcm.decrypt(encrypted_data.nonce, ciphertext_and_tag, None)
        return plaintext # Devuelve el plaintext si todo es correcto
    except InvalidTag:
        # Falla esperada si el tag no coincide (autenticación fallida)
        raise ValueError("Error de autenticacion: Tag invalido o datos corruptos.")
    except Exception as e:
        raise ValueError(f"Error al desencriptar: {e}")