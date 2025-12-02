from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from app.canonicalizer import canonicalize
from app.keystore import b64u_decode
import hashlib
from app.address import address_from_pubkey

class Verifier:

    @staticmethod
    def derive_address_from_pubkey(pubkey_bytes: bytes) -> str:
        #   Deriva una dirección simple desde la llave pública.
        hex_digest = hashlib.sha256(pubkey_bytes).hexdigest()
        return "0x" + hex_digest[-40:] # Se concatena "0x" para indicar que es una dirección hexadecimal

    @staticmethod
    def verify(signed_tx: dict) -> tuple:
        # 1. Verificamos la estructura mínima
        required = ["tx", "signature", "pubkey", "scheme"]
        for field in required:
            if field not in signed_tx:
                return False, f"Falta el campo '{field}' en la transacción firmada"

        if signed_tx["scheme"] != "ed25519":
            return False, "Esquema de firma no soportado (solo ed25519)"

        tx = signed_tx["tx"]

        if not isinstance(tx, dict):
            return False, "tx debe ser un diccionario"

        if "from" not in tx:
            return False, "La transacción no contiene el campo 'from'"

        # 2. Se canonicaliza la transacción original (no firmada)
        try:
            tx_canonical_bytes = canonicalize(tx)
        except Exception as e:
            return False, f"Error al canonicalizar la transacción: {e}"

        # 3. Decodificamos firmamos, en conjunto con la llave pública
        try:
            signature_bytes = b64u_decode(signed_tx["signature"])
            pubkey_bytes = b64u_decode(signed_tx["pubkey"])
        except Exception:
            return False, "Error al decodificar signature/pubkey en Base64URL"


        # 4. Construimos la llave pública Ed25519
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        except Exception:
            return False, "Llave pública inválida"


        # 5. Verificación de la firma Ed25519
        try:
            public_key.verify(signature_bytes, tx_canonical_bytes)
        except InvalidSignature:
            return False, "Firma inválida"
        except Exception as e:
            return False, f"Error al verificar firma: {e}"


        # 6. Derivación de la address y comparación con el formato de transacción tx["from"]
        derived_address = address_from_pubkey(pubkey_bytes)

        if tx["from"] != derived_address:
            return False, (
                f"Address derivado no coincide con 'from': "
                f"{derived_address} != {tx['from']}"
            )

        # Si todo es correcto, se retorna True
        return True, "OK"
