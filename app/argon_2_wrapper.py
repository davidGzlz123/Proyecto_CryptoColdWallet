# Este módulo permite generar claves seguras a partir de contraseñas usando Argon2id.

from __future__ import annotations
import secrets
from typing import Optional, Union
from dataclasses import dataclass
from argon2.low_level import hash_secret_raw, Type

# Configuración por defecto
DEFAULT_SALT_SIZE = 16
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 64 * 1024
DEFAULT_PARALLELISM = 1
DEFAULT_KEY_SIZE = 32

@dataclass
class Argon2Settings:
    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST
    parallelism: int = DEFAULT_PARALLELISM
    key_size: int = DEFAULT_KEY_SIZE
    salt_size: int = DEFAULT_SALT_SIZE

#   Crea un salt aleatorio (sirve para que cada clave sea única).
#   El tamaño del salt debe ser un número entero mayor a cero.
#   Si no se especifica, se utilizará el tamaño por defecto de 16 bytes.

def create_random_salt(length: int = DEFAULT_SALT_SIZE) -> bytes:
    if not isinstance(length, int):
        raise TypeError("El tamaño del salt debe ser un número entero.")
    if length <= 0:
        raise ValueError("El tamaño del salt debe ser mayor a cero.")
    return secrets.token_bytes(length)

#    La función toma una frase y un salt como parámetros y devuelve una clave segura.
#    La frase se puede especificar como un string o como bytes.
#    El salt debe ser de tipo bytes y tener al menos 8 bytes.
#    Si no se especifica, se utiliza la configuración por defecto.
#    Se lanza un TypeError si la contraseña no es texto o bytes.
#    Se lanza un ValueError si el salt es demasiado corto.
def generate_key_from_passphrase(passphrase: Union[str, bytes], salt: bytes, settings: Optional[Argon2Settings] = None) -> bytes:

    if settings is None:
        settings = Argon2Settings()

    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("El salt debe estar en bytes.")
    if len(salt) < 8:
        raise ValueError("El salt es demasiado corto; usa al menos 8 bytes.")

    if isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray)):
        passphrase_bytes = bytes(passphrase)
    else:
        raise TypeError("La contraseña debe ser texto o bytes.")

    key = hash_secret_raw(
        secret=passphrase_bytes,
        salt=salt,
        time_cost=int(settings.time_cost),
        memory_cost=int(settings.memory_cost),
        parallelism=int(settings.parallelism),
        hash_len=int(settings.key_size),
        type=Type.ID,
    )

    return key
