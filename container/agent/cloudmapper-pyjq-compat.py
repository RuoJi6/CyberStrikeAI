"""Compatibility layer for CloudMapper's historical pyjq dependency."""

from jq import all, first  # noqa: F401


def one(program, value):
    """Return exactly one jq result, matching the historical pyjq.one API."""

    results = all(program, value)
    if len(results) != 1:
        raise ValueError(f"expected exactly one jq result, got {len(results)}")
    return results[0]
