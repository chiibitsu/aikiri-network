"""Failures that must never be swallowed."""


class SchemaError(ValueError):
    """A document did not match its closed schema. Reject, never coerce."""


class TrustError(ValueError):
    """A trust anchor could not be established."""


class QuorumError(RuntimeError):
    """Independent sources disagreed, or too few answered. Never a success."""


class WrongChain(SystemExit):
    """An RPC endpoint on another chain than the one trusted."""


class EndpointUnusable(ConnectionError):
    """An endpoint left out of the quorum before its first read. Its message is
    describe()'s, never the error's own."""


class EndpointDropped(ConnectionError):
    """An endpoint dropped for the rest of the run. Its message is describe()'s
    or fixed words and numbers, never the error's own."""


def describe(e: BaseException) -> str:
    """What failed, in words no endpoint can put a key into: the error's type and
    what it wraps, by type name, and the HTTP status. Never a library's message,
    which carries the URL as the library printed it, re-encoded in more ways than
    a scrub can match (a key in a keyed RPC URL is part of that URL)."""
    if isinstance(e, (EndpointUnusable, EndpointDropped)):
        return f"{type(e).__name__}: {e}"
    import re
    names, x = [], e
    status = getattr(getattr(e, "response", None), "status_code", None)
    while isinstance(x, BaseException) and len(names) < 4:
        names.append(type(x).__name__)
        # Retries spent on a status leave no response, only urllib3's own fixed words
        # around the number ("too many 429 error responses"); the number is all we keep.
        if type(x).__name__ == "ResponseError" and (m := re.fullmatch(r"too many (\d{3}) error responses", str(x))):
            status = int(m[1])
        x = x.args[0] if x.args and isinstance(x.args[0], BaseException) else getattr(x, "reason", None)
    if isinstance(status, int):
        names.append(f"HTTP {status}")
    return " / ".join(dict.fromkeys(names))
