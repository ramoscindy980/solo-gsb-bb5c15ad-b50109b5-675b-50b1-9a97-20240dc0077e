"""Core JSON redaction engine.

Rule paths are JSON Pointers (RFC 6901) extended with two wildcards:

* ``*``  matches exactly one segment (an object key or an array index)
* ``**`` matches zero or more consecutive segments

All matching is performed against the *original* document, so removing
array elements never shifts the pointers of subsequent matches.

When several rules hit the same node, a single winner is chosen by, in
order: more literal segments, then fewer wildcard segments, then later
declaration order.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterator

MASK_VALUE = "***"
ACTIONS = ("mask", "remove", "sha256")

_SINGLE = "*"
_DEEP = "**"


class RuleError(ValueError):
    """Raised when a rule path or action is invalid."""


# ---------------------------------------------------------------------------
# JSON Pointer helpers
# ---------------------------------------------------------------------------

def escape_segment(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def unescape_segment(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def parse_pointer(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise RuleError(f"invalid JSON Pointer: {pointer!r}")
    return tuple(unescape_segment(part) for part in pointer.split("/")[1:])


def format_pointer(segments: tuple[str, ...]) -> str:
    return "".join("/" + escape_segment(seg) for seg in segments)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    path: str
    action: str
    index: int
    segments: tuple[str, ...]
    literal_count: int
    wildcard_count: int

    @property
    def precedence(self) -> tuple[int, int, int]:
        # Higher wins: more literal segments, then fewer wildcard
        # segments, then later declaration order.
        return (self.literal_count, -self.wildcard_count, self.index)


def compile_rule(path: str, action: str, index: int) -> Rule:
    if action not in ACTIONS:
        raise RuleError(f"invalid action {action!r}; expected one of {ACTIONS}")
    segments = parse_pointer(path)
    literal_count = sum(1 for seg in segments if seg not in (_SINGLE, _DEEP))
    return Rule(
        path=path,
        action=action,
        index=index,
        segments=segments,
        literal_count=literal_count,
        wildcard_count=len(segments) - literal_count,
    )


def _matches(pattern: tuple[str, ...], pointer: tuple[str, ...]) -> bool:
    if not pattern:
        return not pointer
    head, rest = pattern[0], pattern[1:]
    if head == _DEEP:
        # "**" consumes zero or more segments.
        return any(_matches(rest, pointer[k:]) for k in range(len(pointer) + 1))
    if not pointer:
        return False
    if head == _SINGLE or head == pointer[0]:
        return _matches(rest, pointer[1:])
    return False


# ---------------------------------------------------------------------------
# Traversal & application
# ---------------------------------------------------------------------------

def _iter_nodes(value: Any, segments: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Yield (pointer segments, node) for every node in document order."""
    yield segments, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_nodes(child, segments + (key,))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _iter_nodes(child, segments + (str(idx),))


def _hash_value(value: Any, salt: str) -> str:
    if isinstance(value, str):
        canonical = value
    else:
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{salt}{canonical}".encode("utf-8")).hexdigest()


class _Remove:
    """Sentinel signalling that a node must be dropped by its parent."""


_REMOVE = _Remove()


def _apply(value: Any, segments: tuple[str, ...], ops: dict[tuple[str, ...], Rule], salt: str) -> Any:
    """Rebuild the document, applying ops keyed by original-structure pointers.

    Because the structure is rebuilt rather than mutated in place, array
    removals never disturb the (original) indices used by remaining ops.
    """
    rule = ops.get(segments)
    if rule is not None:
        if rule.action == "remove":
            return _REMOVE
        if rule.action == "mask":
            return MASK_VALUE
        return _hash_value(value, salt)
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            new_child = _apply(child, segments + (key,), ops, salt)
            if new_child is not _REMOVE:
                out[key] = new_child
        return out
    if isinstance(value, list):
        out = []
        for idx, child in enumerate(value):
            new_child = _apply(child, segments + (str(idx),), ops, salt)
            if new_child is not _REMOVE:
                out.append(new_child)
        return out
    return value


def redact(data: Any, rules: list[dict], salt: str = "") -> tuple[Any, list[dict]]:
    """Redact ``data`` according to ``rules``; return (result, audit trail)."""
    compiled = [compile_rule(rule.get("path"), rule.get("action"), i) for i, rule in enumerate(rules)]

    # Match every node of the *original* document against every rule.
    ops: dict[tuple[str, ...], Rule] = {}
    order: list[tuple[str, ...]] = []
    for segments, _node in _iter_nodes(data):
        winner: Rule | None = None
        for rule in compiled:
            if _matches(rule.segments, segments) and (winner is None or rule.precedence > winner.precedence):
                winner = rule
        if winner is not None:
            ops[segments] = winner
            order.append(segments)

    result = _apply(data, (), ops, salt)
    if result is _REMOVE:
        result = None  # the root itself was removed

    audit = []
    for segments in order:
        rule = ops[segments]
        # An op is not applied when an ancestor node was already consumed
        # (removed / masked / hashed) by another op.
        applied = not any(segments[:depth] in ops for depth in range(len(segments)))
        audit.append(
            {
                "pointer": format_pointer(segments),
                "rule": rule.path,
                "rule_index": rule.index,
                "action": rule.action,
                "applied": applied,
            }
        )
    return result, audit
