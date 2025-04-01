from __future__ import annotations

from attrs import define

from aegis_vault.crypto import CryptParameters
from aegis_vault.crypto import MasterKey
from aegis_vault.slots import SlotList


@define
class VaultFileCredentials:
    key: MasterKey
    slots: SlotList

    def decrypt(self, data: bytes, params: CryptParameters) -> bytes:
        return self.key.decrypt(data, params)


@define
class Header:
    slots: SlotList
    params: CryptParameters


@define
class VaultFile:
    header: Header
    db: bytes

    def get_content(self, creds: VaultFileCredentials) -> bytes:
        return creds.decrypt(self.db, self.header.params)
