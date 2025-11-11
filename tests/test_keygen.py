# Prueba simple del módulo keygen

import binascii
import keygen

def main():
    print("Generando llaves Ed25519...")
    private_bytes, public_bytes = keygen.generate_keypair()
    print("Llave privada (hex):", binascii.hexlify(private_bytes).decode())
    print("Llave pública (hex):", keygen.export_pubkey_hex(public_bytes))
    print("Llave pública (base64):", keygen.export_pubkey_base64(public_bytes))

    # Prueba rápida: firmar y verificar un mensaje
    message = b"mensaje de prueba"
    if keygen.CRYPTOGRAPHY_OK:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        private_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

        signature = private_obj.sign(message)
        print("Firma (hex):", binascii.hexlify(signature).decode())
        try:
            public_obj.verify(signature, message)
            print("Verificación exitosa")
        except Exception as e:
            print("Error al verificar:", e)
    else:
        from nacl.signing import SigningKey, VerifyKey
        signing_key = SigningKey(private_bytes)
        verify_key = VerifyKey(public_bytes)
        signature = signing_key.sign(message).signature
        print("Firma (hex):", binascii.hexlify(signature).decode())
        try:
            verify_key.verify(message, signature)
            print("Verificación exitosa")
        except Exception:
            print("Error al verificar")

if __name__ == "__main__":
    main()
