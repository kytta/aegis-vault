from __future__ import annotations

from aegis_vault.crypto import MasterKey


def test_generate_masterkey():
    mkey = MasterKey.generate()

    assert type(mkey.key) is bytes
    assert len(mkey.key) == 32
