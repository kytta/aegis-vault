from __future__ import annotations

from uuid import UUID

from aegis_vault.converter import converter
from aegis_vault.crypto import CryptParameters
from aegis_vault.crypto import ScryptParameters
from aegis_vault.slots import PasswordSlot
from aegis_vault.slots import Slot


def test_structure_crypt_params():
    src = """\
{
    "nonce": "dd4496fe07d3d2bbf7a548b6",
    "tag": "386d009f973a5bfcdd7f2e07c5cc696c"
}
"""

    params = converter.loads(src, CryptParameters)

    assert params == CryptParameters(
        nonce=b'\xddD\x96\xfe\x07\xd3\xd2\xbb\xf7\xa5H\xb6',
        tag=b'8m\x00\x9f\x97:[\xfc\xdd\x7f.\x07\xc5\xccil',
    )


def test_structure_scrypt_params():
    src = """\
{
    "type": 1,
    "uuid": "a05f63ed-c84e-4799-9480-9c7da8bb3356",
    "key": "b769850258bc8672522fc2f183fa41e2fbcbbe095a53697b59443ec4ff11bbc7",
    "key_params": {
        "nonce": "dd4496fe07d3d2bbf7a548b6",
        "tag": "386d009f973a5bfcdd7f2e07c5cc696c"
    },
    "n": 32768,
    "r": 8,
    "p": 1,
    "salt": "c746b485bcbaebd0b6ec93c0bd0ee69880bfbb01981f7a09e7699e0e28794977",
    "repaired": true,
    "is_backup": false
}
"""

    params = converter.loads(src, ScryptParameters)

    assert params == ScryptParameters(
        n=32768,
        r=8,
        p=1,
        salt=b'\xc7F\xb4\x85\xbc\xba\xeb\xd0\xb6\xec\x93\xc0\xbd\x0e\xe6\x98\x80\xbf\xbb\x01\x98\x1fz\t\xe7i\x9e\x0e(yIw',
    )


def test_structure_password_slot():
    src = """\
{
    "type": 1,
    "uuid": "a05f63ed-c84e-4799-9480-9c7da8bb3356",
    "key": "b769850258bc8672522fc2f183fa41e2fbcbbe095a53697b59443ec4ff11bbc7",
    "key_params": {
        "nonce": "dd4496fe07d3d2bbf7a548b6",
        "tag": "386d009f973a5bfcdd7f2e07c5cc696c"
    },
    "n": 32768,
    "r": 8,
    "p": 1,
    "salt": "c746b485bcbaebd0b6ec93c0bd0ee69880bfbb01981f7a09e7699e0e28794977",
    "repaired": true,
    "is_backup": false
}
"""

    slot: Slot = converter.loads(src, Slot)

    assert isinstance(slot, PasswordSlot)
    assert slot == PasswordSlot(
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
