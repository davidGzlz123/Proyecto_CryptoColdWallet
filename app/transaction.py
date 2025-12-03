# Módulo para representar transacciones y obtener sus bytes canónicos.

from typing import Optional, Dict, Any

from app.canonicalizer import canonicalize


def make_tx(sender: str, to: str, value: int, nonce: int, data: Optional[str] = None) -> Dict[str, Any]:
    """
    Crea un diccionario de transacción con los campos básicos.

    sender: dirección que envía (from)
    to: dirección de destino
    value: monto a transferir (entero)
    nonce: número de nonce para evitar replays
    data: campo opcional para datos adicionales
    """
    if not isinstance(sender, str) or not isinstance(to, str):
        raise ValueError("Las direcciones 'from' y 'to' deben ser strings.")

    if not isinstance(value, int) or value < 0:
        raise ValueError("El campo 'value' debe ser un entero no negativo.")

    if not isinstance(nonce, int) or nonce < 0:
        raise ValueError("El campo 'nonce' debe ser un entero no negativo.")

    tx = {
        "from": sender,
        "to": to,
        "value": value,
        "nonce": nonce,
    }

    if data is not None:
        if not isinstance(data, str):
            raise ValueError("El campo 'data' (si se usa) debe ser un string.")
        tx["data"] = data

    return tx


def tx_canonical_bytes(tx: Dict[str, Any]) -> bytes:
    """
    Toma un dict de transacción y devuelve los bytes canónicos
    que se usarán para la firma digital.
    Usa el canonicalizer para garantizar un formato determinista.
    """
    if not isinstance(tx, dict):
        raise ValueError("La transacción debe ser un diccionario.")

    # Aquí podrías validar que existan campos obligatorios:
    required_fields = ["from", "to", "value", "nonce"]
    for field in required_fields:
        if field not in tx:
            raise ValueError(f"Falta el campo obligatorio '{field}' en la transacción.")

    # canonicalize() ya debe devolverte bytes según tus tests
    canon_bytes = canonicalize(tx)

    if not isinstance(canon_bytes, (bytes, bytearray)):
        # por si en algún momento canonicalize devolviera string
        canon_bytes = str(canon_bytes).encode("utf-8")

    return canon_bytes
