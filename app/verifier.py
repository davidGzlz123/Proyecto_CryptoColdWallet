# app/verifier.py

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from app.canonicalizer import canonicalize
from app.keystore import b64u_decode
from app.address import address_from_pubkey


class Verifier:
    """
    Clase encargada de verificar una transacción firmada.

    Flujo:
      1. Verificar que la estructura mínima exista (tx, signature, pubkey, scheme).
      2. Canonicalizar el objeto tx con el mismo canonicalizer usado al firmar.
      3. Decodificar firma y pubkey desde Base64-URL.
      4. Reconstruir la llave pública Ed25519.
      5. Verificar criptográficamente la firma.
      6. Derivar la address a partir de la pubkey y compararla con tx["from"].
         Se aceptan formatos con "0x" y sin "0x".
    """

    @staticmethod
    def derive_address_from_pubkey(pubkey_bytes: bytes) -> str:
        """
        Helper para derivar la dirección a partir de la llave pública.

        Este método es usado en los tests para construir el campo 'from' de
        las transacciones firmadas. Delegamos en address_from_pubkey para
        mantener un único formato de dirección en todo el proyecto.
        """
        return address_from_pubkey(pubkey_bytes)

    @staticmethod
    def verify(signed_tx: dict) -> tuple:
        """
        Verifica una transacción firmada.

        Retorna:
            (True, "OK") si todo es válido.
            (False, "motivo") si alguna verificación falla.
        """

        # 1. Verificar estructura mínima
        required = ["tx", "signature", "pubkey", "scheme"]
        for field in required:
            if field not in signed_tx:
                return (
                    False,
                    f"Falta el campo '{field}' en la transacción firmada",
                )

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

        # 3. Decodificar firma y pubkey desde Base64-URL
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

        # 6. Derivar address a partir de la pubkey y comparar con tx["from"]
        derived_address = address_from_pubkey(pubkey_bytes)  # p.ej. "0xabcdef..."

        # Normalizamos ambas representaciones para admitir:
        # - "0x" + 40 hex
        # - 40 hex sin "0x"
        derived_hex = derived_address.lower()
        if derived_hex.startswith("0x"):
            derived_hex = derived_hex[2:]

        from_field = str(tx["from"]).lower()
        if from_field.startswith("0x"):
            from_field = from_field[2:]

        if from_field != derived_hex:
            return (
                False,
                f"Address derivado no coincide con 'from': "
                f"{derived_address} != {tx['from']}",
            )

        # Todo correcto
        return True, "OK"
