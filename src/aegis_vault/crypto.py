from __future__ import annotations

from attrs import define
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTO_AEAD_KEY_SIZE = 32
CRYPTO_AEAD_TAG_SIZE = 16
CRYPTO_AEAD_NONCE_SIZE = 12

CRYPTO_SCRYPT_N = 1 << 15
CRYPTO_SCRYPT_r = 8
CRYPTO_SCRYPT_p = 1


@define
class CryptParameters:
    nonce: bytes
    tag: bytes


@define
class ScryptParameters:
    n: int
    r: int
    p: int
    salt: bytes


@define
class MasterKey:
    key: bytes

    @classmethod
    def generate(cls) -> MasterKey:
        return cls(key=AESGCM.generate_key(CRYPTO_AEAD_KEY_SIZE * 8))

    def decrypt(self, data: bytes, params: CryptParameters) -> bytes:
        aesgcm = AESGCM(key=self.key)
        return aesgcm.decrypt(
            nonce=params.nonce,
            data=data + params.tag,
            associated_data=None,
        )
