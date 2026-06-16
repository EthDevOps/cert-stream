import pytest

from certwatch.match import (
    InvalidDomain,
    entry_matches_san,
    matches,
    validate_watch_entry,
)


def test_exact_match():
    assert matches("foo.example.org", ["foo.example.org"]) == ["foo.example.org"]
    assert matches("foo.example.org", ["bar.example.org"]) == []


def test_entry_covers_apex():
    assert matches("example.org", ["example.org"]) == ["example.org"]


def test_entry_covers_single_subdomain():
    assert matches("foo.example.org", ["example.org"]) == ["example.org"]


def test_entry_covers_deep_subdomain():
    assert matches("a.b.c.example.org", ["example.org"]) == ["example.org"]


def test_entry_does_not_match_sibling_or_substring():
    assert matches("notexample.org", ["example.org"]) == []
    assert matches("example.org.evil.com", ["example.org"]) == []
    assert matches("ethereum.foundation-scam.com", ["ethereum.foundation"]) == []


def test_wildcard_san_against_entry_apex():
    # *.example.org covers subdomains of example.org → must alert on entry example.org
    assert matches("*.example.org", ["example.org"]) == ["example.org"]


def test_wildcard_san_against_deeper_entry():
    # *.example.org could be foo.example.org → alert on entry foo.example.org
    assert matches("*.example.org", ["foo.example.org"]) == ["foo.example.org"]


def test_wildcard_san_disjoint_from_sibling_entry():
    # *.bar.example.org never expands to anything under foo.example.org
    assert matches("*.bar.example.org", ["foo.example.org"]) == []


def test_wildcard_san_at_or_below_entry():
    # *.foo.example.org expansions all lie under example.org
    assert matches("*.foo.example.org", ["example.org"]) == ["example.org"]


def test_wildcard_in_entry_is_stripped():
    # Entries with leading wildcard are normalized to the apex form.
    assert validate_watch_entry("*.Example.ORG.") == "example.org"


def test_validate_rejects_inner_wildcard():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("foo.*.example.org")


def test_validate_rejects_partial_wildcard():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("*foo.example.org")


def test_validate_rejects_single_label():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("localhost")


def test_validate_rejects_bare_wildcard():
    with pytest.raises(InvalidDomain):
        validate_watch_entry("*.")


def test_normalization():
    assert matches("FOO.Example.ORG.", ["example.org"]) == ["example.org"]


def test_multiple_entries():
    hits = matches("api.ethereum.org", ["ethereum.org", "example.org"])
    assert hits == ["ethereum.org"]


def test_entry_matches_san_direct():
    assert entry_matches_san("example.org", "foo.example.org") is True
    assert entry_matches_san("example.org", "example.org") is True
    assert entry_matches_san("example.org", "*.example.org") is True
    assert entry_matches_san("example.org", "*.foo.example.org") is True
    assert entry_matches_san("foo.example.org", "*.example.org") is True
    assert entry_matches_san("foo.example.org", "*.bar.example.org") is False
    assert entry_matches_san("example.org", "evil-example.org") is False
