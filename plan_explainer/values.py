"""Walking plan values together with their sensitivity masks.

A plan has, next to ``before`` and ``after``, masks (``before_sensitive``, ``after_sensitive``) of the same
shape in which ``true`` marks a sensitive value, and ``after_unknown``, in which ``true`` marks a value that
is only known after apply. Everything that prints a value goes through here, so that a sensitive value is
never written out.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


class _Marker:
    def __init__(self, text: str) -> None:
        self.text = text

    def __repr__(self) -> str:
        return self.text


# Terraform marks what the provider declares sensitive, and not every secret is declared. Anything under
# a name like this is hidden as well.
SECRET_NAME = re.compile(
    r"password|passwd|secret|token|private_key|credential|api_?key|access_?key|connection_string|ssh_key|license_key",
    re.IGNORECASE,
)

REDACTED = _Marker("(sensitive)")
UNKNOWN = _Marker("(known after apply)")
ABSENT = _Marker("(none)")


def sub(mask: Any, key: str | int) -> Any:
    """The part of a mask that belongs to ``key``."""
    if mask is True:
        return True
    if isinstance(mask, dict):
        return mask.get(key, False) if isinstance(key, str) else False
    if isinstance(mask, list) and isinstance(key, int):
        return mask[key] if key < len(mask) else False
    return False


def leaves(obj: Any, keys: tuple[str, ...], mask: Any = False) -> Iterator[Any]:
    """Every value at ``keys``; lists on the way count as 'any element'. Sensitive values are REDACTED."""
    if mask is True:
        yield REDACTED
        return
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from leaves(item, keys, sub(mask, i))
        return
    if not keys:
        yield obj
        return
    if isinstance(obj, dict) and keys[0] in obj:
        yield from leaves(obj[keys[0]], keys[1:], sub(mask, keys[0]))


def raw(obj: Any, *keys: str) -> list[Any]:
    """Like ``leaves`` with no masks: for decisions, never for output."""
    return list(leaves(obj, keys))


def scrub(obj: Any, mask: Any) -> Any:
    """A copy of ``obj`` with every sensitive part replaced."""
    if mask is True:
        return REDACTED
    if isinstance(obj, dict):
        return {k: REDACTED if SECRET_NAME.search(k) else scrub(v, sub(mask, k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, sub(mask, i)) for i, v in enumerate(obj)]
    return obj


def show(value: Any, limit: int = 80) -> str:
    """A short, single-line rendering of a value."""
    if isinstance(value, _Marker):
        return value.text

    def enc(v: Any) -> Any:
        if isinstance(v, _Marker):
            return v.text
        if isinstance(v, dict):
            return {k: enc(x) for k, x in v.items()}
        if isinstance(v, list):
            return [enc(x) for x in v]
        return v

    text = json.dumps(enc(value), ensure_ascii=False, separators=(", ", ": "), sort_keys=True)
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class AttrChange:
    path: str
    before: Any
    after: Any

    def line(self) -> str:
        if self.before is REDACTED and self.after is REDACTED:
            return f"{self.path}: (sensitive value changed)"
        return f"{self.path}: {show(self.before)} → {show(self.after)}"


def attr_changes(
    before: Any, after: Any, before_mask: Any, after_mask: Any, unknown: Any
) -> list[AttrChange]:
    """Leaf-level differences between two values, with sensitive and unknown parts marked."""
    out: list[AttrChange] = []
    _diff((), before, after, before_mask, after_mask, unknown, out)
    return out


def _path(parts: tuple[str | int, ...]) -> str:
    text = ""
    for p in parts:
        text += f"[{p}]" if isinstance(p, int) else (f".{p}" if text else p)
    return text or "(value)"


def _diff(path, b, a, bm, am, unk, out) -> None:  # noqa: ANN001
    if unk is True:
        out.append(AttrChange(_path(path), _mask(b, bm), UNKNOWN))
        return
    if bm is True or am is True:
        if b != a:
            out.append(AttrChange(_path(path), _mask(b, bm), _mask(a, am)))
        return
    if isinstance(b, dict | type(None)) and isinstance(a, dict | type(None)) and (b or a):
        b, a = b or {}, a or {}
        keys = sorted(set(b) | set(a) | (set(unk) if isinstance(unk, dict) else set()))
        for k in keys:
            hide = bool(SECRET_NAME.search(k))
            _diff(
                path + (k,),
                b.get(k),
                a.get(k),
                True if hide else sub(bm, k),
                True if hide else sub(am, k),
                sub(unk, k),
                out,
            )
        return
    if isinstance(b, list | type(None)) and isinstance(a, list | type(None)) and (b or a):
        b, a = b or [], a or []
        for i in range(max(len(b), len(a), len(unk) if isinstance(unk, list) else 0)):
            _diff(
                path + (i,),
                b[i] if i < len(b) else None,
                a[i] if i < len(a) else None,
                sub(bm, i),
                sub(am, i),
                sub(unk, i),
                out,
            )
        return
    if b == a:
        return
    out.append(AttrChange(_path(path), _mask(b, bm), _mask(a, am)))


def _mask(value: Any, mask: Any) -> Any:
    if value is None:
        return ABSENT
    return scrub(value, mask)
