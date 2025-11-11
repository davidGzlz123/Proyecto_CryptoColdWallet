import binascii
import keygen

def main():
    print("Generando llaves Ed25519...")
    priv, pub = keygen.generate_keypair()
    print("Llave privada (hex):", binascii.hexlify(priv).decode())
    print("Llave pública (hex):", keygen.export_pubkey_hex(pub))
    print("Llave pública (base64):", keygen.export_pubkey_base64(pub))

    # Prueba rápida: firmar y verificar un mensaje
    mensaje = b"mensaje de prueba"
    if keygen.CRYPTOGRAPHY_OK:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
        pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub)

        firma = priv_obj.sign(mensaje)
        print("Firma (hex):", binascii.hexlify(firma).decode())
        try:
            pub_obj.verify(firma, mensaje)
            print("Verificación exitosa")
        except Exception as e:
            print("Error al verificar:", e)
    else:
        from nacl.signing import SigningKey, VerifyKey
        sk = SigningKey(priv)
        vk = VerifyKey(pub)
        firma = sk.sign(mensaje).signature
        print("Firma (hex):", binascii.hexlify(firma).decode())
        try:
            vk.verify(mensaje, firma)
            print("Verificación exitosa")
        except Exception:
            print("Error al verificar")

if __name__ == "__main__":
    main()
