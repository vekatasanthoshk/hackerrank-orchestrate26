"""Where the Anthropic API key for the two model stages comes from.

Claude Code cloud environments reserve ``ANTHROPIC_API_KEY`` for the session's own sign-in and
do not pass it into the container, so the key can also be supplied as
``AUDIT_ANTHROPIC_API_KEY``. Either name works in a local ``.env`` (main.py loads it).
The key is only handed to the SDK client; it is never printed or logged.
"""
import os

KEY_VARS = ("ANTHROPIC_API_KEY", "AUDIT_ANTHROPIC_API_KEY")


def api_key():
    """The first non-empty key variable, or None."""
    return next((os.environ[v].strip() for v in KEY_VARS if os.environ.get(v, "").strip()), None)


def client():
    import anthropic  # imported lazily so key-less runs need no SDK

    return anthropic.Anthropic(api_key=api_key())
