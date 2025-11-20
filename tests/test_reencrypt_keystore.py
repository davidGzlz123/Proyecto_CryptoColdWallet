# test_reencrypt_keystore.py
import json
import os
import base64
import hashlib
import pytest

# Ajusta este import al módulo donde pegaste el código que me diste.
# Si el archivo se llama keystore.py y está en package app -> from app.keystore import ...
from app.keystore import (
    generate_ed25519_keypair,
    make_keystore,
    save_keystore,
    load_keystore,
    unlock_keystore,
    change_keystore_passphrase,
    compute_checksum,
    b64u, b64u_decode
)


def read_file_text(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def write_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def test_reencrypt_happy_path(tmp_path):
#   Flujo completo para cambiar la passphrase de un keystore:
#   Generar par de llaves
#     Crear keystore en disco con pass_old
# -   Desbloquear con pass_old (verifica que funcione)
# -   Cambiar passphrase a pass_new (change_keystore_passphrase)
# - Verificar:
#     unlock_keystore con pass_new funciona y devuelve la misma private PEM
#     unlock_keystore con pass_old falla
#     el ciphertext en el keystore cambió
#     el checksum se recalculó correctamente

    pass_old = "mi-pass-vieja-123"
    pass_new = "mi-pass-nueva-456"

    # 1) Generar llaves
    priv_pem, pub_raw = generate_ed25519_keypair()

    # 2) Crear keystore y guardarlo en disco
    keystore = make_keystore(priv_pem, pub_raw, pass_old)
    path = tmp_path / "keystore.json"
    save_keystore(str(path), keystore)

    # Guardamos algunos valores originales para comparar
    original_ciphertext_b64 = keystore['crypto']['ciphertext']
    original_checksum = keystore['checksum']['value']

    # 3) Desbloquear con pass_old (debe funcionar)
    priv1, pub1 = unlock_keystore(keystore, pass_old)
    assert priv1 == priv_pem
    assert pub1 == pub_raw

    # 4) Cambiar passphrase (esto también guarda en disco)
    keystore_after = change_keystore_passphrase(str(path), pass_old, pass_new)

    # 5) Cargar keystore modificado y verificar que ciphertext cambió
    keystore_loaded = load_keystore(str(path))
    new_ciphertext_b64 = keystore_loaded['crypto']['ciphertext']
    new_checksum = keystore_loaded['checksum']['value']

    assert new_ciphertext_b64 != original_ciphertext_b64, "El ciphertext debería haber cambiado."
    assert new_checksum != original_checksum, "El checksum debería haberse actualizado."

    # 6) Verificar que unlock con la passphrase nueva funciona y la private PEM es la misma
    priv2, pub2 = unlock_keystore(keystore_loaded, pass_new)
    assert priv2 == priv_pem, "La private PEM debe conservarse después del re-encrypt."
    assert pub2 == pub_raw, "La public key no debe cambiar."

    # 7) Verificar que unlock con passphrase vieja falla
    with pytest.raises(ValueError):
        unlock_keystore(keystore_loaded, pass_old)

    # 8) Verificar checksum coincide con compute_checksum usando pubkey y ciphertext bytes
    pub_bytes = b64u_decode(keystore_loaded['pubkey'])
    ciphertext_bytes = b64u_decode(keystore_loaded['crypto']['ciphertext'])
    recomputed = compute_checksum(pub_bytes, ciphertext_bytes)
    assert recomputed == keystore_loaded['checksum']['value'], "Checksum recalculado no coincide con el guardado."


def test_change_passphrase_with_wrong_old_fails(tmp_path):
#   Intentar cambiar passphrase pasando una passphrase antigua incorrecta debe lanzar ValueError.
    pass_old = "correct-old-pass"
    wrong_old = "wrong-old-pass"
    pass_new = "new-pass-789"

    priv_pem, pub_raw = generate_ed25519_keypair()
    keystore = make_keystore(priv_pem, pub_raw, pass_old)
    path = tmp_path / "keystore2.json"
    save_keystore(str(path), keystore)

    with pytest.raises(ValueError) as exc:
        change_keystore_passphrase(str(path), wrong_old, pass_new)

    assert "Passphrase antigua incorrecta" in str(exc.value) or "incorrecta" in str(exc.value).lower()


def test_checksum_tamper_is_detected(tmp_path):
#    Si se altera el ciphertext en el JSON sin actualizar el checksum, unlock_keystore debe detectar mismatch y levantar ValueError.

    pass_old = "pass-checksum"
    priv_pem, pub_raw = generate_ed25519_keypair()
    keystore = make_keystore(priv_pem, pub_raw, pass_old)
    path = tmp_path / "keystore3.json"
    save_keystore(str(path), keystore)

    # Cargar y corromper ciphertext (sin actualizar checksum)
    k = load_keystore(str(path))
    # Generar bytes aleatorios y codificarlos en b64u para simular corrupción
    bad_bytes = b"corrupto-por-prueba"
    k['crypto']['ciphertext'] = b64u(bad_bytes)

    # Guardamos el keystore corrupto
    save_keystore(str(path), k)

    # Ahora unlock_keystore debe detectar checksum inválido
    with pytest.raises(ValueError) as exc:
        load = load_keystore(str(path))
        # unlock_keystore primero calcula checksum y lanzará ValueError si no coincide
        unlock_keystore(load, pass_old)

    assert "Checksum invalido" in str(exc.value) or "corrupto" in str(exc.value).lower()
