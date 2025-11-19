# tests/test_signer.py
# Pruebas para el módulo Signer.

import os
import pytest
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)
from app.signer import Signer
from app.keystore import generate_ed25519_keypair, b64u_decode
from app.canonicalizer import canonicalize

# Fixture para la generación de un par de llaves Ed25519
@pytest.fixture
def keypair():
    return generate_ed25519_keypair()

# Test 1: Verificación de que el output o JSON firmado tenga la estructura correcta
def test_signer_structure(keypair):
    priv_pem, _ = keypair
    # Transacción de prueba
    tx = {
        "from": "0x123...",
        "to": "0x456...",
        "amount": 50,
        "nonce": 1
    }
    signed = Signer.sign(tx, priv_pem)
    # Verificamos campos básicos
    assert "tx" in signed
    assert signed["tx"] == tx
    assert "signature" in signed
    assert "pubkey" in signed
    assert signed["scheme"] == "ed25519"

# Test 2: Verificación criptográfica de que la firma es válida
# Se simula lo que haría un verificador externo
def test_signature_verification_manual(keypair):
    priv_pem, pub_raw = keypair
    tx = {"mensaje": "hola mundo", "val": 42}

    # Firmamos con nuestra clase Signer
    result = Signer.sign(tx, priv_pem)
    signature = b64u_decode(result["signature"])
    pubkey_en_recibo = b64u_decode(result["pubkey"])

    # Canonicalizamos manualmente para verificar
    msg_bytes = canonicalize(tx)

    # Verificamos con cryptography la firma
    priv_obj = load_pem_private_key(priv_pem, password=None)
    pub_obj = priv_obj.public_key()

    # Se lanza la excepción si la firma es falsa
    try:
        pub_obj.verify(signature, msg_bytes)
    except Exception as e:
        pytest.fail(f"La firma generada no es válida: {e}")  
    # Verificamos que la llave pública en el recibo sea la correcta
    assert pubkey_en_recibo == pub_raw

# Test 3: Verificación de que el orden de las llaves no cambie la firma
# Probamos que el canonicalizer esté trabajando dentro del Signer
def test_canonicalization_consistency(keypair):
    priv_pem, _ = keypair
    
    # Definimos dos objetos iguales semánticamente, diferentes en bytes directos
    tx_a = {"a": 1, "b": 2}
    tx_b = {"b": 2, "a": 1} # Orden de llaves diferente
    # Firmamos ambos
    res_a = Signer.sign(tx_a, priv_pem) 
    res_b = Signer.sign(tx_b, priv_pem)

    # Las firmas deben ser idénticas, sino, el canonicalizer falló
    assert res_a["signature"] == res_b["signature"]