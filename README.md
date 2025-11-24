# README de Proyecto_CryptoColdWallet

### Uso de la herramienta de firma (sign_tx.py)

La herramienta `tools/sign_tx.py` permite firmar transacciones a partir de un archivo JSON usando el keystore cifrado (`mi_keystore.json`).

1. Crear un archivo de transacción, por ejemplo `inbox/tx1.json`:

   ```json
   {
     "from": "0xAAA",
     "to": "0xBBB",
     "value": 100,
     "nonce": 1
   }
