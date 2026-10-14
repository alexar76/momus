"""MOMUS engine — orchestration: scan → sign findings → independent verify → (treasury) payout."""

__all__ = ["Scanner", "ScanReport", "Verifier"]


def __getattr__(name):
    # Coverage/quality jobs do not serve the oracle API or need its signing stack.
    # Keep the public imports compatible without booting every scanner dependency.
    if name in ("Scanner", "ScanReport"):
        from momus.engine import scanner
        return getattr(scanner, name)
    if name == "Verifier":
        from momus.engine.verify import Verifier
        return Verifier
    raise AttributeError(name)
