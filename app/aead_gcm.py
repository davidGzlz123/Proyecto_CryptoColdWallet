# app/aead_gcm.py
# Módulo AEAD. Implementación de AES-256-GCM con helpers Base64.

import os
from base64 import b64encode, b64decode
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Configuración Criptográfica ---
AES_KEY_SIZE = 32   # 256 bits para AES-256
GCM_NONCE_SIZE = 12 # 96 bits para GCM
GCM_TAG_SIZE = 16   # 128 bits para autenticación


# -------------------------------------------------------------
# Helpers Base64
# -------------------------------------------------------------

def b64_to_bytes(s: str) -> bytes:
    """Decodifica un string Base64 (UTF-8) a bytes."""
    return b64decode(s.encode('utf-8'))

def bytes_to_b64(b: bytes) -> str:
    """Codifica bytes a Base64 (UTF-8)."""
    return b64encode(b).decode('utf-8')


# -------------------------------------------------------------
# Clase EncryptedData
# -------------------------------------------------------------

@dataclass
class EncryptedData:
    """
    Estructura para almacenar los componentes de AES-GCM:
    - ciphertext (bytes)
    - nonce (bytes)
    - tag (bytes)
    """
    ciphertext: bytes
    nonce: bytes
    tag: bytes

    def to_dict(self) -> dict:
        """Convierte los campos de bytes a Base64 para JSON."""
        return {
            "ciphertext_b64": bytes_to_b64(self.ciphertext),
            "nonce_b64": bytes_to_b64(self.nonce),
            "tag_b64": bytes_to_b64(self.tag),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedData":
        """
        Reconstruye un EncryptedData desde un dict con Base64.
        (Nombre requerido por los tests)
        """
        return cls(
            ciphertext=b64_to_bytes(data["ciphertext_b64"]),
            nonce=b64_to_bytes(data["nonce_b64"]),
            tag=b64_to_bytes(data["tag_b64"]),
        )

    @staticmethod
    def un_dict(data: dict) -> 'EncryptedData':
        """Versión legacy del método de deserialización."""
        return EncryptedData(
            ciphertext=b64_to_bytes(data["ciphertext_b64"]),
            nonce=b64_to_bytes(data["nonce_b64"]),
            tag=b64_to_bytes(data["tag_b64"]),
        )


# -------------------------------------------------------------
# AES-256-GCM Encryption
# -------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes) -> EncryptedData:
    """Cifra un plaintext usando AES-256-GCM."""
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"La llave debe ser de {AES_KEY_SIZE} bytes.")

    nonce = os.urandom(GCM_NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext = ciphertext_and_tag[:-GCM_TAG_SIZE]
    tag = ciphertext_and_tag[-GCM_TAG_SIZE:]

    return EncryptedData(ciphertext=ciphertext, nonce=nonce, tag=tag)


# -------------------------------------------------------------
# AES-256-GCM Decryption
# -------------------------------------------------------------

def decrypt(key: bytes, encrypted_data: EncryptedData) -> bytes:
    """Descifra un EncryptedData usando AES-256-GCM."""
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise ValueError(f"La llave debe ser de {AES_KEY_SIZE} bytes.")

    aesgcm = AESGCM(key)

    ciphertext_and_tag = encrypted_data.ciphertext + encrypted_data.tag

    try:
        plaintext = aesgcm.decrypt(encrypted_data.nonce, ciphertext_and_tag, None)
        return plaintext

    except InvalidTag:
        # Mensaje EXACTO que requieren los tests (sin acentos)
        raise ValueError("Error de autenticacion: Tag invalido o datos corruptos.")

    except Exception as e:
        raise ValueError(f"Error al desencriptar: {e}")
