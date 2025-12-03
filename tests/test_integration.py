# Test de Integración Completo para la Aplicación de la Cold Wallet

import json
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
# Si el script está en la raíz, usamos current_dir. Si está en tests/, subimos uno.
if current_dir.endswith("tests"):
    project_root = os.path.dirname(current_dir)
else:
    project_root = current_dir
sys.path.insert(0, project_root)
from app.keystore import (
    generate_ed25519_keypair,
    make_keystore,
    unlock_keystore
)
from app.signer import Signer
from app.verifier import Verifier
from app.address import address_from_pubkey
from app.nonce_manager import get_nonce


INBOX = "inbox"
OUTBOX = "outbox"

# --- Helper de simulación de transacciones ---
def make_tx_simulation(sender: str, to: str, value: int, nonce: int) -> dict:
    # Simula la creación de una transacción.
    return {
        "from": sender,
        "to": to,
        "value": value,
        "nonce": nonce
    }


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_tx_from_inbox(name="tx1.json"):
    path = os.path.join(INBOX, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
    
# --- Test de Integración Completo ---
def test_full_lifecycle_flow():
    print("\n--- INICIO: Test de Ciclo de Vida Completo ---")
    
    # Paso 1: Definimos las credenciales
    passphrase = "password-seguro-test"
    print("[1] Pashhphrase definida para el test.")

    # Paso 2: Generamos el par de llaves Ed25519
    print("[2] Generando par de llaves Ed25519...")
    priv_pem, pub_raw = generate_ed25519_keypair()
    assert len(priv_pem) > 0
    assert len(pub_raw) == 32

    # Paso 3: Creamos al Keystore 
    print("[3] Creando Keystore (Cifrando llave privada)...")
    ks = make_keystore(priv_pem, pub_raw, passphrase)
    assert ks["version"] == 1
    assert "crypto" in ks

    # Paso 4: Desbloqueamos el Keystore
    print("[4] Desbloqueando Keystore (Simulando usuario)...")
    recovered_priv, recovered_pub = unlock_keystore(ks, passphrase)
    assert recovered_priv == priv_pem
    assert recovered_pub == pub_raw
    
    # Derivamos la dirección desde la llave pública 
    my_address = address_from_pubkey(recovered_pub)
    print(f"    -> Address: {my_address}")

    # Paso 5: Creamos la transacción a firmar [tx]
    print("[5] Construyendo objeto de Transacción...")
    # En un test aislado, el nonce empieza en 0
    tx = make_tx_simulation(my_address, "0xDestinoTest", 1000, 0)

    # Paso 6: Firmamos la transacción 
    print("[6] Firmando Transacción...")
    signed_tx = Signer.sign(tx, recovered_priv)
    assert signed_tx["scheme"] == "ed25519"
    assert "signature" in signed_tx

    # Paso 7: Verificacamos la transacción firmada
    print("[7] Verificación en la Red (Verifier)...")
    is_valid, msg = Verifier.verify(signed_tx)
    
    if not is_valid:
        raise Exception(f"La verificación falló: {msg}")
    
    print("Ciclo completo exitoso :D.")


# --- Tests Negativos Simulando Ataques y Errores ---
def test_error_cases():
    print("\n--- INICIO: Tests de Errores y Ataques ---")
    
    # Setup básico de keystore y transacción
    passphrase = "pass"
    priv, pub = generate_ed25519_keypair()
    ks = make_keystore(priv, pub, passphrase)
    address = address_from_pubkey(pub)
    tx = make_tx_simulation(address, "0xBob", 50, 0)
    signed_tx = Signer.sign(tx, priv)

    # Caso A: Prueba de Passphrase Incorrecto
    print("[A] Probando Passphrase Incorrecto...")
    try:
        unlock_keystore(ks, "password-INCORRECTA")
        raise Exception("ERROR: Debió fallar con password incorrecta")
    except ValueError as e:
        print(f"    -> Correctamente rechazado: {e}")

    # Caso B: Prueba de Transacción Alterada (Tampering)
    print("[B] Probando Transacción Alterada (Tampering)...")
    malicious_tx = json.loads(json.dumps(signed_tx))
    malicious_tx["tx"]["value"] = 9999999 # Hacker cambia el monto
    
    is_valid, msg = Verifier.verify(malicious_tx)
    if is_valid:
        raise Exception("ERROR: El verificador aceptó una tx alterada")
    print(f"    -> Correctamente rechazado: {msg}")

    # Caso C: Prueba de Llave Pública Modificada (Identidad Falsa)
    print("[C] Probando Pubkey no coincidente (Address Mismatch)...")
    # Generamos llaves de un atacante 
    priv_atk, pub_atk = generate_ed25519_keypair()
    # El atacante firma la transacción (tx) que dice ser de la Víctima
    signed_fake = Signer.sign(tx, priv_atk)
    
    is_valid, msg = Verifier.verify(signed_fake)
    if is_valid:
        raise Exception("ERROR: El verificador aceptó firma de identidad falsa")
    print(f"    -> Correctamente rechazado: {msg}")
    print("Todos los tests negativos pasaron.")


if __name__ == "__main__":
    # Modo script manual
    try:
        test_full_lifecycle_flow()
        test_error_cases()
        print("\nSCRIPT TERMINADO CON ÉXITO")
    except Exception as e:
        print(f"\nFALLO EN EL TEST: {e}")
        sys.exit(1)