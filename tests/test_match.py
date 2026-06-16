import pytest

from certwatch.match import (
    InvalidDomain,
    matches,
    patterns_intersect,
    validate_watch_entry,
)


def test_exact_match():
    assert matches("foo.example.org", ["foo.example.org"]) == ["foo.example.org"]
    assert matches("foo.example.org", ["bar.example.org"]) == []


def test_wildcard_entry_matches_single_label():
    assert matches("foo.example.org", ["*.example.org"]) == ["*.example.org"]
    assert matches("bar.example.org", ["*.example.org"]) == ["*.example.org"]


def test_wildcard_entry_does_not_match_apex():
    assert matches("example.org", ["*.example.org"]) == []


def test_wildcard_entry_does_not_match_deeper_label():
    assert matches("foo.bar.example.org", ["*.example.org"]) == []


def test_wildcard_san_against_exact_entry():
    # cert SAN *.example.org covers our entry foo.example.org → must alert
    assert matches("*.example.org", ["foo.example.org"]) == ["foo.example.org"]


def test_wildcard_san_against_wildcard_entry():
    assert matches("*.example.org", ["*.example.org"]) == ["*.example.org"]


def test_no_overlap_between_disjoint_wildcards():
    # *.example.org and *.foo.example.org cover disjoint FQDN sets
    assert matches("*.example.org", ["*.foo.example.org"]) == []
    assert matches("*.foo.example.org", ["*.example.org"]) == []


def test_unrelated_substrings_do_not_match():
    assert matches("ethereum.foundation-scam.com", ["ethereum.foundation"]) == []
    assert matches("ethereum-foo.com", ["*.ethereum.org"]) == []


def test_normalization():
    assert matches("FOO.Example.ORG.", ["foo.example.org"]) == ["foo.example.org"]


def test_multiple_entries():
    hits = matches("api.ethereum.org", ["*.ethereum.org", "*.example.org"])
    assert hits == ["*.ethereum.org"]


def test_patterns_intersect_disjoint_lengths():
    assert patterns_intersect("a.b.c", "*.b.c") is True
    assert patterns_intersect("a.b.c", "*.b.c.d") is False


def test_validate_rejects_inner_wildcard():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("foo.*.example.org")


def test_validate_rejects_partial_wildcard():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("*foo.example.org")


def test_validate_accepts_wildcard_and_normalizes():
    assert validate_watch_entry("*.Example.ORG.") == "*.example.org"


def test_validate_rejects_single_label():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("localhost")
