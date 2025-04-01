from __future__ import annotations

from enum import IntEnum
from uuid import UUID

from attrs import define
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from aegis_vault.crypto import CryptParameters
from aegis_vault.crypto import MasterKey
from aegis_vault.crypto import ScryptParameters


@define
class Slot:
    class Type(IntEnum):
        RAW = 0x00
        PASSWORD = 0x01
        BIOMETRIC = 0x02

    uuid: UUID
    key: bytes
    key_params: CryptParameters

    def get_key(self, key: bytes) -> MasterKey:
        aesgcm = AESGCM(key)
        decrypted_key = aesgcm.decrypt(
            nonce=self.key_params.nonce,
            data=self.key + self.key_params.tag,
            associated_data=None,
        )
        return MasterKey(decrypted_key)


SlotList = dict[UUID, Slot]


@define
class RawSlot(Slot):
    pass


@define
class PasswordSlot(Slot):
    scrypt_params: ScryptParameters
    repaired: bool
    is_backup: bool

    def derive_key(self, password: str) -> bytes:
        password_bytes = password.encode("utf8")
        kdf = Scrypt(
            salt=self.scrypt_params.salt,
            length=32,
            n=self.scrypt_params.n,
            r=self.scrypt_params.r,
            p=self.scrypt_params.p,
        )
        return kdf.derive(password_bytes)


@define
class BiometricSlot(Slot):
    pass


slot_type_map: dict[type[Slot], Slot.Type] = {
    RawSlot: Slot.Type.RAW,
    PasswordSlot: Slot.Type.PASSWORD,
    BiometricSlot: Slot.Type.BIOMETRIC,
}
