# app/signer.py
# Módulo de irma de transacciones.

import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

# Importamos el canonicalizador
from app.canonicalizer import canonicalize
from app.keystore import b64u

# Definimos la clase estática para firmar transacciones donde se firma una
# transacción dada una llave privada en formato PEM
class Signer:
    @staticmethod
    def sign(tx: dict, private_key_pem: bytes) -> dict:

        # Realizamos validaciones básicas
        if not isinstance(tx, dict):
            raise ValueError("La transacción debe ser un diccionario.")
        if not isinstance(private_key_pem, bytes):
            raise ValueError("La llave privada deben ser bytes en formato PEM.")

        # Realizamos la canonicalización de la transacción
        # Convertimos el JSON a bytes deterministas usando el módulo canonicalizer
        try:
            tx_canonical_bytes = canonicalize(tx)
        except Exception as e:
            raise ValueError(f"Error al canonicalizar la transacción: {e}")

        # Cargamos la llave privada desde PEM 
        try:
            private_key = load_pem_private_key(private_key_pem, password=None)
            if not isinstance(private_key, Ed25519PrivateKey):
                 raise ValueError("La llave proporcionada no es Ed25519.")
        except Exception as e:
            raise ValueError(f"Error al cargar la llave privada: {e}")

        # Firmamos la transacción canonicalizada
        # Ed25519 firma los bytes directamente
        signature_bytes = private_key.sign(tx_canonical_bytes)

        # Extraemos la llave pública desde la llave privada 
        # La necesitamos en el output para que cualquiera pueda verificar la firma después
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

        # Finalmente, construimos el diccionario JSON de la transacción firmada
        signed_tx = {
            "tx": tx,
            "signature": b64u(signature_bytes),
            "pubkey": b64u(public_key_bytes),
            "scheme": "ed25519"
        }
        # Regresamos la transacción firmada
        return signed_tx