from collections.abc import Iterable


class InvalidDomain(ValueError):
    pass


def normalize_san(san: str) -> str:
    s = san.strip().lower().rstrip(".")
    if not s:
        raise InvalidDomain("empty domain")
    return s


def validate_watch_entry(value: str) -> str:
    """Normalize and validate a watch-list entry. Accepts FQDN or leading-wildcard."""
    v = normalize_san(value)
    labels = v.split(".")
    if len(labels) < 2:
        raise InvalidDomain(f"too few labels: {value!r}")
    for i, lbl in enumerate(labels):
        if not lbl:
            raise InvalidDomain(f"empty label in {value!r}")
        if "*" in lbl:
            if i != 0 or lbl != "*":
                raise InvalidDomain(
                    f"wildcard only allowed as the leftmost full label, got {value!r}"
                )
    return v


def patterns_intersect(a: str, b: str) -> bool:
    """True iff the FQDN sets covered by patterns a and b overlap.

    Both inputs are normalized FQDNs that may use a single leading `*` label
    (CABF wildcard semantics — covers exactly one label position).
    """
    al = a.split(".")
    bl = b.split(".")
    if len(al) != len(bl):
        return False
    for i, (x, y) in enumerate(zip(al, bl)):
        if x == y:
            continue
        if i == 0 and (x == "*" or y == "*"):
            continue
        return False
    return True


def matches(san: str, entries: Iterable[str]) -> list[str]:
    """Return the watch entries whose FQDN set overlaps the SAN's FQDN set."""
    try:
        s = normalize_san(san)
    except InvalidDomain:
        return []
    hits: list[str] = []
    for e in entries:
        if patterns_intersect(s, e):
            hits.append(e)
    return hits
