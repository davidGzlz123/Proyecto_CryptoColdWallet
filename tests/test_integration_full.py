# tests/test_integration_full.py
# Test de integración "end-to-end" para Crypto Cold Wallet CLI
# Ejecuta todas las acciones solicitadas:
# 1. Crear keystore
# 2. Obtener address
# 3. Crear tx con nonce_db
# 4. Firmar tx
# 5. Guardarla en outbox
# 6. Procesarla desde inbox
# 7. Verificar y mover a verified
# 8. Asegurar que el nonce se incrementó

import os
import shutil
import json
import tempfile
import pathlib
import time

import pytest
import sys

# Añadir ruta del proyecto para permitir `import app.*`
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Importar funciones del proyecto (asume que `app` es importable desde la raíz del proyecto)
from app.keystore import generate_ed25519_keypair, make_keystore, save_keystore, load_keystore, decrypt_private_key, b64u_decode
from app.address import address_from_pubkey
from app.signer import Signer
from app.verifier import Verifier
from app.nonce_manager import get_nonce, increment_nonce, validate_nonce

# Los tests deben ejecutarse en un entorno aislado; usamos un directorio temporal

def test_integration_end_to_end(tmp_path):
    # --- Preparar estructura de directorios (simular OUTBOX/INBOX/VERIFIED/REJECTED) ---
    base = tmp_path
    outbox = base / "outbox"
    inbox = base / "inbox"
    verified = base / "verified"
    rejected = base / "rejected"
    for d in (outbox, inbox, verified, rejected):
        d.mkdir()

    # --- 1) Crear keystore (sin interacción) ---
    keystore_file = base / "keystore_test.json"
    passphrase = "integration-passphrase"

    priv, pub = generate_ed25519_keypair()
    ks = make_keystore(priv, pub, passphrase)
    save_keystore(str(keystore_file), ks)
    assert keystore_file.exists(), "Keystore no fue creado"

    # --- 2) Obtener address ---
    loaded = load_keystore(str(keystore_file))
    pub_bytes = b64u_decode(loaded["pubkey"]) if isinstance(loaded["pubkey"], str) else loaded["pubkey"]
    my_address = address_from_pubkey(pub_bytes)
    assert isinstance(my_address, str) and len(my_address) > 0, "Address inválida"

    initial_nonce = get_nonce(my_address)

    # --- 3) Crear tx con nonce_db ---
    tx = {
        "from": my_address,
        "to": "0xDEADBEEF",
        "value": 123,
        "nonce": initial_nonce
    }

    # --- 4) Firmar tx ---
    priv_pem = decrypt_private_key(loaded["crypto"], passphrase)
    signed_tx = Signer.sign(tx, priv_pem)
    assert "signature" in signed_tx and "tx" in signed_tx, "Firma no tiene el formato esperado"

    # --- 5) Guardarla en outbox ---
    tx_filename = f"tx_{signed_tx['signature'][:8]}.json"
    out_path = outbox / tx_filename
    with open(out_path, "w") as f:
        json.dump(signed_tx, f, indent=2)
    assert out_path.exists(), "Transacción no se guardó en outbox"

    # --- 6) Mover a inbox (simula transmisión) ---
    inbox_path = inbox / tx_filename
    shutil.copy(out_path, inbox_path)
    assert inbox_path.exists(), "Transacción no fue copiada a inbox"

    # --- 7) Procesarla desde inbox: verificar y mover a verified ---
    # Emular el mismo comportamiento que interactive_process()
    with open(inbox_path, "r") as f:
        loaded_signed = json.load(f)

    is_valid, msg = Verifier.verify(loaded_signed)
    assert is_valid, f"Firma inválida en Verifier.verify: {msg}"

    sender_addr = loaded_signed["tx"]["from"]
    tx_nonce = loaded_signed["tx"]["nonce"]

    # Validamos nonce y luego incrementamos
    validate_nonce(sender_addr, tx_nonce)
    increment_nonce(sender_addr)

    # Mover archivo a verified
    dst_verified = verified / tx_filename
    shutil.move(str(inbox_path), str(dst_verified))
    assert dst_verified.exists(), "No se movió el archivo a verified"

    # --- 8) Asegurar que el nonce se incrementó ---
    new_nonce = get_nonce(my_address)
    assert new_nonce == initial_nonce + 1, f"El nonce no se incrementó: initial={initial_nonce}, new={new_nonce}"

    # Limpieza (opcional): verificar que outbox permanezca con el archivo original
    assert out_path.exists(), "El archivo original en outbox desapareció"

    # Si llegamos aquí, el flujo completo funcionó
    print("[OK] Test de integración end-to-end completado correctamente.")

