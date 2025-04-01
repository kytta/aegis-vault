from __future__ import annotations

from uuid import UUID

from aegis_vault.crypto import CryptParameters
from aegis_vault.crypto import ScryptParameters
from aegis_vault.slots import PasswordSlot


def test_derive_key():
    slot = PasswordSlot(
        uuid=UUID("a05f63ed-c84e-4799-9480-9c7da8bb3356"),
        key=b'\xb7i\x85\x02X\xbc\x86rR/\xc2\xf1\x83\xfaA\xe2\xfb\xcb\xbe\tZSi{YD>\xc4\xff\x11\xbb\xc7',
        key_params=CryptParameters(
            nonce=b'\xddD\x96\xfe\x07\xd3\xd2\xbb\xf7\xa5H\xb6',
            tag=b'8m\x00\x9f\x97:[\xfc\xdd\x7f.\x07\xc5\xccil',
        ),
        scrypt_params=ScryptParameters(
            n=32768,
            r=8,
            p=1,
            salt=b'\xc7F\xb4\x85\xbc\xba\xeb\xd0\xb6\xec\x93\xc0\xbd\x0e\xe6\x98\x80\xbf\xbb\x01\x98\x1fz\t\xe7i\x9e\x0e(yIw',
        ),
        repaired=True,
        is_backup=False,
    )
    password = "correct horse battery staple"

    assert slot.derive_key(
        password,
    ) == b'\xfb\xa5\xf6\x0cG4\x04\xac ZP,\xb0\x9a\x07\xc0\xc2\x88\xc9\xd8L\xd9|"($%2\x01D<\x8a'
