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
    Regresa una tupla (priv_bytes, pub_bytes)
    """
    if CRYPTOGRAPHY_OK:
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_bytes, pub_bytes
    else:
        sk = SigningKey.generate()
        vk = sk.verify_key
        return sk.encode(), vk.encode()


def export_pubkey_hex(pub_bytes):
    """Convierte la llave pública a texto en formato hex."""
    return binascii.hexlify(pub_bytes).decode('ascii')


def export_pubkey_base64(pub_bytes):
    """Convierte la llave pública a texto en formato base64."""
    return b64encode(pub_bytes).decode('ascii')
