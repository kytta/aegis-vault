from __future__ import annotations

import getpass
import json
from pathlib import Path

from aegis_vault.converter import make_converter
from aegis_vault.crypto import MasterKey
from aegis_vault.slots import PasswordSlot
from aegis_vault.vault import VaultFile
from aegis_vault.vault import VaultFileCredentials


converter = make_converter()


def decrypt_password_slot(slots: list[PasswordSlot], password: str) -> MasterKey | None:
    for slot in slots:
        try:
            key = slot.derive_key(password)
            mkey = slot.get_key(key)

            if not slot.repaired:
                raise NotImplementedError()

            return mkey
        except Exception:
            raise
            # continue

    return None


export = Path(
    "/Users/nikita/Backups/Lava Lake/Aegis/aegis-backup-20250323-122220.json",
)

with export.open("rb") as fd:
    data = json.load(fd)

# assert len(data['header']['slots']) == 1

vault = converter.structure(data, VaultFile)

password_slots = [
    s for u, s in vault.header.slots.items() if isinstance(s, PasswordSlot)
]

password = getpass.getpass()
key = decrypt_password_slot(password_slots, password)
if key is None:
    print("could not derive key from slots:")
    print(password_slots)
    raise SystemExit(69)
creds = VaultFileCredentials(key, vault.header.slots)
content = vault.get_content(creds)

vault_content = json.loads(content)

# print(vault_content['entries'])

print({e["issuer"]: e["info"] for e in vault_content["entries"]})

# key_data = data['header']['slots'][0]
# db = b64decode(data['db'])

# kdf = Scrypt(
#     salt=key_data['salt'].encode(),
#     length=32,
#     n=key_data['n'],
#     r=key_data['r'],
#     p=key_data['p'],
# )

# key = kdf.derive(password)

# aesgcm = AESGCM(key)
# print(aesgcm.decrypt(
#     bytes.fromhex(key_data['key_params']['nonce']),
#     db,
#     None,
# ))
