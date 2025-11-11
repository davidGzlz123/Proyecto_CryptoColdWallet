# Módulo para generar llaves Ed25519 y exportar la pública en base64 o hex

from base64 import b64encode
import binascii

# Intento usar cryptography primero
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_OK = True
except:
    CRYPTOGRAPHY_OK = False

# Si no hay cryptography, intento con pynacl
try:
    from nacl.signing import SigningKey, VerifyKey
    PYNACL_OK = True
except:
    PYNACL_OK = False


if not (CRYPTOGRAPHY_OK or PYNACL_OK):
    raise ImportError("Falta instalar cryptography o pynacl para usar este módulo.")


def generate_keypair():
    """
    Genera una llave privada y pública Ed25519
    Regresa una tupla (private_bytes, public_bytes)
    """
    if CRYPTOGRAPHY_OK:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_bytes, public_bytes
    else:
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        return signing_key.encode(), verify_key.encode()


def export_pubkey_hex(public_bytes):
    """Convierte la llave pública a texto en formato hex."""
    return binascii.hexlify(public_bytes).decode('ascii')


def export_pubkey_base64(public_bytes):
    """Convierte la llave pública a texto en formato base64."""
    return b64encode(public_bytes).decode('ascii')
