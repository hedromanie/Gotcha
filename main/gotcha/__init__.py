# Lazy: do not import Gotcha at package import time.
__all__ = ["Gotcha"]

def __getattr__(name):
    if name == "Gotcha":
        from gotcha.app import Gotcha
        return Gotcha
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
