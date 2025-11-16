import os
import json
import tempfile
import pytest

import sys
# Obtiene la ruta absoluta de la carpeta 'tests' (donde está este archivo)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Sube un nivel para llegar a la raíz del proyecto ('Proyecto_CryptoColdWallet')
project_root = os.path.dirname(current_dir)
# Añade la raíz del proyecto al path de búsqueda de Python
sys.path.insert(0, project_root)

# Importamos las funciones de nuestro script de keystore
from app.keystore import (
    generate_ed25519_keypair,
    make_keystore,
    save_keystore,
    load_keystore,
    unlock_keystore,
    b64u,
    b64u_decode #
)

# Fixtures de Pytest 

@pytest.fixture
def keypair():
    return generate_ed25519_keypair()

@pytest.fixture
def passphrase():
    return "mi-pass-123"

# Tests básicos de creación, guardado, carga y desbloqueo

# Test de creación y desbloqueo correcto del keystore
def test_unlock_ok(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "ks.json")
        save_keystore(path, ks)
        loaded = load_keystore(path)
        priv2, pub2 = unlock_keystore(loaded, passphrase)
        assert priv2 == priv_pem
        assert pub2 == pub_raw


# Test de desbloqueo con passphrase incorrecto
def test_unlock_bad_passphrase(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    
    # El test ahora espera un ValueError que contenga este texto en específico
    with pytest.raises(ValueError, match="ERROR: Passphrase incorrecto"):
        print("   (Intentando desbloquear con clave incorrecta, esperamos que falle...)")
        unlock_keystore(ks, "incorrecta")
    print("   (Falló como se esperaba)")


# Test de detección de corrupción mediante el checksum
def test_checksum_detection(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    ks_corrupt = json.loads(json.dumps(ks))
    
    # Corrompemos el ciphertext
    ks_corrupt["crypto"]["ciphertext"] = b64u(b"datos corruptos")
    
    # El test ahora espera un ValueError que contenga este texto
    with pytest.raises(ValueError, match="ERROR: Checksum invalido"):
        unlock_keystore(ks_corrupt, passphrase)
    print("   (Corrupción de ciphertext detectada por checksum, OK)")


# Test de carga de keystore con formato inválido
def test_load_invalid_format(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{\"campo_incorrecto\": 123}")
    with pytest.raises(ValueError, match="Formato de keystore inválido"):
        load_keystore(str(bad))

# Test de múltiples rondas de creación y desbloqueo del keystore
def test_multiple_rounds():
    for i in range(5):
        priv, pub = generate_ed25519_keypair()
        passw = f"pass-{i}"
        ks = make_keystore(priv, pub, passw)
        priv2, pub2 = unlock_keystore(ks, passw)
        assert priv2 == priv
        assert pub2 == pub

# Test de estabilidad con passphrases aleatorias 
def test_stability_with_random_passphrases():
    import random
    import string
    for _ in range(3):
        priv, pub = generate_ed25519_keypair()
        passw = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        ks = make_keystore(priv, pub, passw)
        priv2, pub2 = unlock_keystore(ks, passw)
        assert priv2 == priv
        assert pub2 == pub


# Test de corrupción de la llave pública detectada por el checksum
def test_unlock_corrupted_pubkey(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)

    # Corrompemos la pubkey (que es parte del checksum)
    ks_corrupt = json.loads(json.dumps(ks))
    ks_corrupt["pubkey"] = b64u(b"basura publica") # 'YWJj'

    # Esperamos que falle por el checksum
    with pytest.raises(ValueError, match="ERROR: Checksum invalido"):
        unlock_keystore(ks_corrupt, passphrase)
    print("   (Corrupción de pubkey detectada por checksum, OK)")

# Test de inconsistencia entre la llave pública y la llave privada cifrada
def test_unlock_key_consistency_fail(keypair, passphrase):
    priv_pem, pub_raw = keypair
    ks = make_keystore(priv_pem, pub_raw, passphrase)

    # Creamos un keystore corrupto a propósito
    ks_corrupt = json.loads(json.dumps(ks))
    
    # Generamos una llave pública 'basura' que no tiene nada que ver con la privada
    basura_pub_bytes = os.urandom(32) 
    
    # Recalculamos el checksum para que sea 'válido' con la llave pública basura
    # Así nos saltamos la primera barrera del checksum 
    
    # Importamos la función compute_checksum
    from app.keystore import compute_checksum 
    
    ciphertext_bytes = b64u_decode(ks["crypto"]["ciphertext"])
    nuevo_checksum = compute_checksum(basura_pub_bytes, ciphertext_bytes)
    
    # Inyectamos la 'basura' en el keystore
    ks_corrupt["pubkey"] = b64u(basura_pub_bytes)
    ks_corrupt["checksum"]["value"] = nuevo_checksum

    # El checksum debido a la manipulación previa pasará, pero el 'unlock' debe fallar en la 
    # verificación de consistencia 
    with pytest.raises(ValueError, match="Clave privada inválida después de desencriptar."):
        unlock_keystore(ks_corrupt, passphrase)
    print("   (Inconsistencia de llaves detectada, OK)")

