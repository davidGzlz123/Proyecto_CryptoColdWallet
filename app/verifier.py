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
        #   Puedes ajustar el algoritmo si tu proyecto usa otro formato.
        return hashlib.sha256(pubkey_bytes).hexdigest()[:40]

    @staticmethod
    def verify(signed_tx: dict) -> tuple:
        #   Verifica una transacción firmada.
        #   Retorna:
            #   (True, "OK") si es válida
            #   (False, "motivo") si no pasa alguna verificación

        # 1. Verificar estructura mínima
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

        # 2. Canonicalizar la transacción original (no firmada)
        try:
            tx_canonical_bytes = canonicalize(tx)
        except Exception as e:
            return False, f"Error al canonicalizar la transacción: {e}"

        # 3. Decodificar firma y pubkey
        try:
            signature_bytes = b64u_decode(signed_tx["signature"])
            pubkey_bytes = b64u_decode(signed_tx["pubkey"])
        except Exception:
            return False, "Error al decodificar signature/pubkey en Base64URL"


        # 4. Construir llave pública Ed25519
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        except Exception:
            return False, "Llave pública inválida"


        # 5. Verificar la firma Ed25519
        try:
            public_key.verify(signature_bytes, tx_canonical_bytes)
        except InvalidSignature:
            return False, "Firma inválida"
        except Exception as e:
            return False, f"Error al verificar firma: {e}"


        # 6. Derivar address y comparar con tx["from"]
        derived_address = address_from_pubkey(pubkey_bytes)

        if tx["from"] != derived_address:
            return False, (
                f"Address derivado no coincide con 'from': "
                f"{derived_address} != {tx['from']}"
            )


        # Todo correcto
        return True, "OK"
