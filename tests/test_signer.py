# tests/test_signer.py
# Pruebas para el módulo Signer y el comportamiento de firmado/verificación.

import os
import pytest
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import sys

# Ajustar path para importar módulos desde 'app/'
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.signer import Signer
from app.keystore import generate_ed25519_keypair, b64u_decode
from app.canonicalizer import canonicalize


# ---------------------------------------------------------------------------
# FIXTURE PARA GENERAR LLAVES
# Se genera un par de llaves Ed25519 para las pruebas.
# ---------------------------------------------------------------------------
@pytest.fixture
def keypair():
    return generate_ed25519_keypair()


# ---------------------------------------------------------------------------
# TEST 1: Estructura del JSON firmado
# Se verifica que la salida tenga: tx, signature, pubkey, scheme.
# ---------------------------------------------------------------------------
def test_signer_structure(keypair):
    priv_pem, _ = keypair

    tx = {
        "from": "0x123...",
        "to": "0x456...",
        "amount": 50,
        "nonce": 1
    }

    signed = Signer.sign(tx, priv_pem)

    assert "tx" in signed
    assert signed["tx"] == tx
    assert "signature" in signed
    assert "pubkey" in signed
    assert signed["scheme"] == "ed25519"


# ---------------------------------------------------------------------------
# TEST 2: Verificación criptográfica manual
# Se verifica que la firma sea correcta usando cryptography directamente.
# ---------------------------------------------------------------------------
def test_signature_verification_manual(keypair):
    priv_pem, pub_raw = keypair
    tx = {"mensaje": "hola mundo", "val": 42}

    # Firmamos
    result = Signer.sign(tx, priv_pem)
    signature = b64u_decode(result["signature"])
    pubkey_en_recibo = b64u_decode(result["pubkey"])

    # Obtenemos bytes canónicos
    msg_bytes = canonicalize(tx)

    # Obtenemos objetos de cryptography
    priv_obj = load_pem_private_key(priv_pem, password=None)
    pub_obj = priv_obj.public_key()

    # Si la firma no es válida, cryptography lanza
    try:
        pub_obj.verify(signature, msg_bytes)
    except Exception as e:
        pytest.fail(f"La firma generada no es válida: {e}")

    # Validamos que la pubkey del recibo coincida con la real
    assert pubkey_en_recibo == pub_raw


# ---------------------------------------------------------------------------
# TEST 3: Determinismo con canonicalización interna
# Firmar dicts con distinto orden de llaves debe generar la misma firma.
# ---------------------------------------------------------------------------
def test_canonicalization_consistency(keypair):
    priv_pem, _ = keypair

    tx_a = {"a": 1, "b": 2}
    tx_b = {"b": 2, "a": 1}

    res_a = Signer.sign(tx_a, priv_pem)
    res_b = Signer.sign(tx_b, priv_pem)

    assert res_a["signature"] == res_b["signature"]


# ---------------------------------------------------------------------------
# TEST 4 (Día 18): La firma DEBE cambiar si cambia la transacción
# Asegura que la firma depende estrictamente del contenido.
# ---------------------------------------------------------------------------
def test_signature_changes_when_tx_changes(keypair):
    priv_pem, _ = keypair

    tx1 = {"from": "0xAAA", "to": "0xBBB", "amount": 10, "nonce": 1}
    tx2 = {"from": "0xAAA", "to": "0xBBB", "amount": 11, "nonce": 1}  # cambia amount

    sig1 = Signer.sign(tx1, priv_pem)["signature"]
    sig2 = Signer.sign(tx2, priv_pem)["signature"]

    assert sig1 != sig2


# ---------------------------------------------------------------------------
# TEST 5 (Día 18): Tampering detection
# Si un atacante modifica la transacción dentro del JSON firmado,
# la verificación debe fallar.
# ---------------------------------------------------------------------------
def test_tampered_tx_should_fail_verification(keypair):
    priv_pem, pub_raw = keypair

    # Transacción válida
    tx = {"from": "0xAAA", "to": "0xBBB", "amount": 15, "nonce": 3}
    signed = Signer.sign(tx, priv_pem)

    # Verificación original (debe pasar)
    original_signature = signed["signature"]
    original_pubkey = signed["pubkey"]

    # Ahora TAMPERING: cambiamos el "amount"
    tampered = dict(signed)
    tampered_tx = dict(tampered["tx"])
    tampered_tx["amount"] = 9999
    tampered["tx"] = tampered_tx

    # Para verificar, usamos cryptography directamente
    tampered_msg_bytes = canonicalize(tampered_tx)
    tampered_sig = b64u_decode(original_signature)

    # Obtenemos objeto pubkey real
    priv_obj = load_pem_private_key(priv_pem, password=None)
    pub_obj = priv_obj.public_key()

    # Aquí esperamos un fallo
    with pytest.raises(Exception):
        pub_obj.verify(tampered_sig, tampered_msg_bytes)
