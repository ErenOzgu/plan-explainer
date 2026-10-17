"""Optional configuration: extra stateful types, the mass-destroy threshold, and waivers with reasons."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    """The configuration file is not valid."""


@dataclass(frozen=True)
class Waiver:
    rule: str
    address: str  # an address, or a pattern with * and ?
    reason: str


@dataclass(frozen=True)
class Config:
    stateful_types: frozenset[str] = frozenset()
    mass_destroy: int = 10
    waivers: tuple[Waiver, ...] = ()


_TOP = {"stateful_types", "mass_destroy", "waive"}


def parse(text: str, known_rules: set[str] | None = None) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"not valid TOML: {exc}") from exc
    unknown = sorted(set(data) - _TOP)
    if unknown:
        raise ConfigError(f"unknown setting {unknown[0]!r} (known: {', '.join(sorted(_TOP))})")
    types = data.get("stateful_types", [])
    if not isinstance(types, list) or not all(isinstance(t, str) and t for t in types):
        raise ConfigError("stateful_types must be a list of resource type names")
    mass = data.get("mass_destroy", 10)
    if not isinstance(mass, int) or isinstance(mass, bool) or mass < 1:
        raise ConfigError("mass_destroy must be a whole number of at least 1")
    waivers = []
    for i, w in enumerate(data.get("waive", []), 1):
        if not isinstance(w, dict):
            raise ConfigError(f"waive #{i} must be a table")
        extra = sorted(set(w) - {"rule", "address", "reason"})
        if extra:
            raise ConfigError(f"waive #{i}: unknown key {extra[0]!r}")
        for key in ("rule", "address", "reason"):
            if not isinstance(w.get(key), str) or not w[key].strip():
                raise ConfigError(
                    f"waive #{i}: {key!r} is required"
                    + (" (say why it is acceptable)" if key == "reason" else "")
                )
        if known_rules is not None and w["rule"] not in known_rules:
            raise ConfigError(f"waive #{i}: unknown rule {w['rule']!r} (see `plan-explainer rules`)")
        waivers.append(Waiver(w["rule"], w["address"], w["reason"].strip()))
    return Config(frozenset(types), mass, tuple(waivers))


def load(path: str | Path, known_rules: set[str] | None = None) -> Config:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    return parse(text, known_rules)
