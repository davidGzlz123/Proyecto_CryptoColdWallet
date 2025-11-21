import json
import os

from app.signer import Signer
from app.verifier import Verifier
from app.keystore import load_keystore, unlock_keystore


INBOX = "inbox"
OUTBOX = "outbox"


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_tx_from_inbox(name="tx1.json"):
    path = os.path.join(INBOX, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_integration_test():

    print("=== TEST DE INTEGRACIÓN ===")

    keystore = load_keystore("mi_keystore.json")
    priv_pem, pubkey_raw = unlock_keystore(keystore, "1234")

    tx = load_tx_from_inbox("tx1.json")
    print("TX cargada desde inbox:", tx)

    signed_tx = Signer.sign(tx, priv_pem)
    print("TX firmada:", signed_tx)

    outbox_path = os.path.join(OUTBOX, "tx1_signed.json")
    write_json(outbox_path, signed_tx)
    print(f"TX firmada guardada en {outbox_path}")

    # ------------------------------
    # Verificación correcta
    # ------------------------------
    ok, msg = Verifier.verify(signed_tx)
    print("Verificación original:", (ok, msg))

    if not ok:
        raise Exception("La verificación falló en una TX recién firmada")

    print("Verificación correcta")

    # ------------------------------
    # Corrupción
    # ------------------------------
    corrupted = dict(signed_tx)
    corrupted["tx"] = dict(signed_tx["tx"])
    corrupted["tx"]["value"] = 99999

    print("Probando TX corrupta...")

    ok2, msg2 = Verifier.verify(corrupted)
    print("Verificación con corrupción:", (ok2, msg2))

    if ok2:
        raise Exception("ERROR: La verificación NO detectó corrupción")

    print("Detector de errores funcionando correctamente")
    print("=== TEST COMPLETO ===")


if __name__ == "__main__":
    run_integration_test()
