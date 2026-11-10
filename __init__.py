"""injection-range: a prompt-injection fire drill for your own Hermes agent. See README.md."""
try:
    from .plugin import register
except ImportError:
    # A test runner collecting this folder imports the file with no parent package. Hermes
    # always loads it as a package, so a real import failure still surfaces there.
    if __package__:
        raise

__all__ = ["register"]
