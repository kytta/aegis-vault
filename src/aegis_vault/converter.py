from __future__ import annotations

from functools import partial
from typing import Any
from typing import TYPE_CHECKING
from uuid import UUID

from cattrs import BaseConverter
from cattrs.preconf import wrap
from cattrs.preconf.json import JsonConverter
from cattrs.preconf.json import make_converter as make_json_converter
from cattrs.strategies import configure_tagged_union
from cattrs.strategies import include_subclasses

from aegis_vault.slots import PasswordSlot
from aegis_vault.slots import Slot
from aegis_vault.slots import slot_type_map

if TYPE_CHECKING:
    from cattrs.dispatch import StructureHook
    from cattrs.dispatch import UnstructureHook


def make_pwslot_structure_hook(converter: BaseConverter) -> StructureHook:
    old_hook = converter.get_structure_hook(PasswordSlot)

    def structure_password_slot(val: dict[str, Any], _) -> PasswordSlot:
        return old_hook(
            {
                **val,
                "scrypt_params": val,
            },
            PasswordSlot,
        )

    return structure_password_slot


def make_pwslot_unstructure_hook(converter: BaseConverter) -> UnstructureHook:
    old_hook = converter.get_unstructure_hook(PasswordSlot)

    def unstructure_password_slot(val: PasswordSlot) -> dict[str, Any]:
        unstructured: dict[str, Any] = old_hook(val)
        result = {
            **unstructured,
            **unstructured["scrypt_params"],
        }
        del result["scrypt_params"]
        return result

    return unstructure_password_slot


@wrap(JsonConverter)
def make_converter() -> JsonConverter:
    converter = make_json_converter()

    # serialize bytes as hex
    converter.register_unstructure_hook(bytes, lambda v: v.hex())
    converter.register_structure_hook(bytes, lambda v, _: bytes.fromhex(v))

    # serialize uuids as hex with dashes
    converter.register_unstructure_hook(UUID, str)
    converter.register_structure_hook(UUID, lambda u, _: UUID(hex=u))

    # serialize password slots as flat objects
    converter.register_structure_hook(
        PasswordSlot, make_pwslot_structure_hook(converter),
    )
    converter.register_unstructure_hook(
        PasswordSlot, make_pwslot_unstructure_hook(converter),
    )

    slot_union_strategy = partial(
        configure_tagged_union,
        tag_generator=slot_type_map.get,
        tag_name="type",
    )
    include_subclasses(Slot, converter, union_strategy=slot_union_strategy)

    return converter


converter = make_converter()
