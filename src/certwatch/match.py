from collections.abc import Iterable


class InvalidDomain(ValueError):
    pass


def normalize_san(san: str) -> str:
    s = san.strip().lower().rstrip(".")
    if not s:
        raise InvalidDomain("empty domain")
    return s


def validate_watch_entry(value: str) -> str:
    """Normalize a watch-list entry to a bare FQDN.

    A leading ``*.`` is stripped — entries cover the apex and every subdomain,
    so the wildcard is redundant.
    """
    v = normalize_san(value)
    if v.startswith("*."):
        v = v[2:]
    if not v:
        raise InvalidDomain(f"empty domain after stripping wildcard: {value!r}")
    labels = v.split(".")
    if len(labels) < 2:
        raise InvalidDomain(f"too few labels: {value!r}")
    for lbl in labels:
        if not lbl:
            raise InvalidDomain(f"empty label in {value!r}")
        if "*" in lbl:
            raise InvalidDomain(f"wildcard not allowed inside labels: {value!r}")
    return v


def _covers(entry: str, fqdn: str) -> bool:
    return fqdn == entry or fqdn.endswith("." + entry)


def entry_matches_san(entry: str, san: str) -> bool:
    """True iff the SAN's FQDN set overlaps the entry (apex + all subdomains).

    The SAN may be a plain FQDN or a CABF leading-wildcard form ``*.X``;
    the entry is a plain FQDN.
    """
    if san.startswith("*."):
        base = san[2:]
        # Wildcard SAN covers all single-label children of `base`.
        # Overlap with entry iff:
        #   - some child y.base lies under the entry (i.e. base is at or below entry), or
        #   - the entry itself is a single-label child of base.
        if _covers(entry, base):
            return True
        entry_labels = entry.split(".")
        base_labels = base.split(".")
        if (
            len(entry_labels) == len(base_labels) + 1
            and entry_labels[1:] == base_labels
        ):
            return True
        return False
    return _covers(entry, san)


def matches(san: str, entries: Iterable[str]) -> list[str]:
    """Return the watch entries whose FQDN set overlaps the SAN's FQDN set."""
    try:
        s = normalize_san(san)
    except InvalidDomain:
        return []
    return [e for e in entries if entry_matches_san(e, s)]
