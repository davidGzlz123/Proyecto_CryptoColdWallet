# tests/test_verifier.py
# Pruebas sobre el módulo Verifier para la verificación de transacciones firmadas.

import pytest
import json
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.signer import Signer
from app.verifier import Verifier
from app.keystore import generate_ed25519_keypair

# Fixture para generar un par de llaves 
@pytest.fixture
def keypair():
    return generate_ed25519_keypair()

# Fixture para una transacción firmada válida
@pytest.fixture
def valid_signed_tx(keypair):
    priv_pem, pub_raw = keypair
    # Empleamos la dirección derivada de la llave pública por medio del Verifier 
    address = Verifier.derive_address_from_pubkey(pub_raw)
    
    tx = {
        "from": address,
        "to": "0xDestinoValido",
        "value": 100,
        "nonce": 1
    }
    return Signer.sign(tx, priv_pem)

# Test 1: Caso Positivo - Transacción válida
def test_verify_success(valid_signed_tx):
    is_valid, msg = Verifier.verify(valid_signed_tx)
    assert is_valid is True
    assert msg == "OK"

# Test 2: Caso Negativo - Firma truncada
def test_verify_truncated_signature(valid_signed_tx):
    bad_tx = json.loads(json.dumps(valid_signed_tx))
    # Cortamos la firma a la mitad para invalidarla
    original_sig = bad_tx["signature"]
    bad_tx["signature"] = original_sig[:len(original_sig)//2]
    
    is_valid, msg = Verifier.verify(bad_tx)
    assert is_valid is False
    # El mensaje puede variar depende de si falla b64 decode o verify
    assert "Error" in msg or "Firma" in msg

# Test 3: Caso Negativo - Mismatch de Address (Identidad)
def test_verify_address_mismatch(valid_signed_tx):
    # Obtenemos la transacción original 
    tx_original = valid_signed_tx["tx"]
    # Generamos una identidad de "Hacker" que intentará firmar la transacción
    priv_hacker, pub_hacker = generate_ed25519_keypair()
    # El hacker firma la transacción original
    bad_signed_tx = Signer.sign(tx_original, priv_hacker)
    
    # Verificamos que falle por mismatch de address la verificación
    is_valid, msg = Verifier.verify(bad_signed_tx)
    
    assert is_valid is False
    assert "Address derivado no coincide" in msg

# Test 4: Caso Negativo - Transacción alterada después de la firma (tampering)
def test_verify_tampered_tx(valid_signed_tx):
    bad_tx = json.loads(json.dumps(valid_signed_tx))
    # Cambiamos el monto
    bad_tx["tx"]["value"] = 9999999
    
    is_valid, msg = Verifier.verify(bad_tx)
    assert is_valid is False
    assert "Firma inválida" in msg