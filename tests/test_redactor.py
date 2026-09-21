import hashlib

import pytest

from app.redactor import MASK_VALUE, RuleError, redact


def rule(path, action):
    return {"path": path, "action": action}


def test_mask_with_single_level_wildcard():
    data = {"users": [{"password": "p1", "name": "a"}, {"password": "p2", "name": "b"}]}
    result, audit = redact(data, [rule("/users/*/password", "mask")])
    assert result == {"users": [{"password": MASK_VALUE, "name": "a"}, {"password": MASK_VALUE, "name": "b"}]}
    assert [e["pointer"] for e in audit] == ["/users/0/password", "/users/1/password"]
    assert all(e["action"] == "mask" and e["applied"] for e in audit)


def test_deep_wildcard_matches_any_depth():
    data = {"a": {"secret": 1, "b": {"secret": 2, "c": {"secret": 3}}}, "secret": 0}
    result, audit = redact(data, [rule("/**/secret", "remove")])
    assert result == {"a": {"b": {"c": {}}}}
    # audit follows document order (depth-first over the original structure)
    assert [e["pointer"] for e in audit] == ["/a/secret", "/a/b/secret", "/a/b/c/secret", "/secret"]


def test_double_star_matches_zero_segments():
    data = {"a": {"b": 1}}
    result, audit = redact(data, [rule("/a/**", "mask")])
    # '**' consumes zero segments at /a itself, so the whole subtree is masked
    assert result == {"a": MASK_VALUE}
    assert audit[0]["pointer"] == "/a"


def test_precedence_more_literal_segments_wins():
    data = {"users": {"admin": {"password": "x"}}}
    rules = [rule("/users/*/password", "mask"), rule("/users/admin/password", "remove")]
    result, audit = redact(data, rules)
    assert result == {"users": {"admin": {}}}
    assert audit[0]["rule"] == "/users/admin/password"
    assert audit[0]["action"] == "remove"


def test_precedence_fewer_wildcards_wins():
    data = {"a": {"b": {"c": 1}}}
    # Both have exactly one literal segment; '/a/**' has fewer wildcards.
    rules = [rule("/*/*/c", "mask"), rule("/a/**", "remove")]
    result, audit = redact(data, rules)
    assert result == {}
    assert audit[0]["rule"] == "/a/**"


def test_precedence_later_declaration_wins():
    data = {"a": {"b": 1}}
    # Identical specificity -> the later rule wins.
    rules = [rule("/a/*", "mask"), rule("/*/b", "remove")]
    result, audit = redact(data, rules)
    assert result == {"a": {}}
    assert audit[0]["rule"] == "/*/b"
    assert audit[0]["rule_index"] == 1


def test_array_removals_do_not_shift_pointers():
    data = {"a": [10, 11, 12, 13, 14]}
    rules = [rule("/a/1", "remove"), rule("/a/3", "remove")]
    result, audit = redact(data, rules)
    # Original indices 1 (11) and 3 (13) are removed.
    assert result == {"a": [10, 12, 14]}
    assert [e["pointer"] for e in audit] == ["/a/1", "/a/3"]
    assert all(e["applied"] for e in audit)


def test_remove_and_wildcard_on_same_array():
    data = ["keep", "drop", "keep2", "drop2"]
    result, _ = redact(data, [rule("/*", "mask"), rule("/1", "remove"), rule("/3", "remove")])
    assert result == [MASK_VALUE, MASK_VALUE]


def test_ancestor_removal_skips_descendant_op():
    data = {"a": {"b": {"c": 1}}, "z": 2}
    rules = [rule("/a", "remove"), rule("/a/b/c", "mask")]
    result, audit = redact(data, rules)
    assert result == {"z": 2}
    by_pointer = {e["pointer"]: e for e in audit}
    assert by_pointer["/a"]["applied"] is True
    assert by_pointer["/a/b/c"]["applied"] is False


def test_sha256_hashes_strings_with_salt():
    data = {"secret": "hello"}
    result, audit = redact(data, [rule("/secret", "sha256")], salt="s1")
    expected = hashlib.sha256(b"s1hello").hexdigest()
    assert result == {"secret": expected}
    assert audit[0]["action"] == "sha256"


def test_sha256_hashes_non_string_values_canonically():
    data = {"obj": {"x": 1, "y": [True, None]}}
    result, _ = redact(data, [rule("/obj", "sha256")], salt="pepper")
    canonical = '{"x":1,"y":[true,null]}'
    expected = hashlib.sha256(f"pepper{canonical}".encode()).hexdigest()
    assert result == {"obj": expected}


def test_salt_changes_hash():
    data = {"v": "same"}
    r1, _ = redact(data, [rule("/v", "sha256")], salt="one")
    r2, _ = redact(data, [rule("/v", "sha256")], salt="two")
    assert r1 != r2


def test_json_pointer_escaping():
    data = {"a/b~c": {"d": 1}}
    result, audit = redact(data, [rule("/a~1b~0c/d", "mask")])
    assert result == {"a/b~c": {"d": MASK_VALUE}}
    assert audit[0]["pointer"] == "/a~1b~0c/d"


def test_root_mask_and_remove():
    result, audit = redact({"x": 1}, [rule("", "mask")])
    assert result == MASK_VALUE
    assert audit[0]["pointer"] == ""

    result, _ = redact({"x": 1}, [rule("", "remove")])
    assert result is None


def test_no_rules_returns_document_unchanged():
    data = {"a": [1, {"b": "c"}]}
    result, audit = redact(data, [])
    assert result == data
    assert audit == []


def test_invalid_action_and_pointer_raise():
    with pytest.raises(RuleError):
        redact({}, [rule("/a", "burn")])
    with pytest.raises(RuleError):
        redact({}, [rule("not-a-pointer", "mask")])


def test_literal_key_matching_array_index():
    data = {"items": ["a", "b", "c"]}
    result, _ = redact(data, [rule("/items/0", "mask")])
    assert result == {"items": [MASK_VALUE, "b", "c"]}
