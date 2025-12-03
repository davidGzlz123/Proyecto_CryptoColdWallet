# Crypto Cold Wallet 

**Implementación de una Cold Wallet en Python.**

Este proyecto implementa una arquitectura segura para la generación, almacenamiento y firma de transacciones de activos digitales en un entorno local y aislado. 
Utiliza un modelo de sistema de archivos (`Inbox`/`Outbox`) para simular la propagación de transacciones en una red descentralizada sin conexión a internet.

---

## Tecnologías Implementadas en la Wallet

La seguridad y funcionamiento del sistema se basan en las siguientes primitivas criptográficas y estándares:

* **Firma Digital:** Algoritmo **Ed25519** (Curva de Edwards) para la autenticidad de las transacciones.
* **Cifrado de Keystore:** **AES-256-GCM** para proteger la clave privada en reposo, garantizando confidencialidad e integridad.
* **Derivación de Claves (KDF):** **Argon2id** (resistente a ataques de GPU/Side-Channel) para derivar claves maestras desde la *passphrase* del usuario.
* **Identidad Pública:** Direcciones derivadas mediante **SHA-256** (truncado a los últimos 20 bytes).
* **Canonicalización:** Implementación del estándar **RFC 8785 (JCS)** para asegurar que los objetos JSON de las transacciones sean deterministas antes de firmarse.
* **Arquitectura de Red Simulada:** Uso de directorios locales (`outbox/`, `inbox/`, `verified/`) para emular el flujo de una *Mempool* y un *Ledger*.

---
