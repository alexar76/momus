"""MOMUS — the adversarial-audit satellite.

Momus was the Greek daimon of blame and mockery, son of Nyx. His canonical demand — that
Hephaestus's man be built with a window in his chest so his thoughts could be inspected — is
the oldest surviving argument for auditability: a system you cannot see into cannot be trusted.
For saying so out loud he was thrown off Olympus, which is also the right posture for a red
team: a tolerated adversary who lives in your own house and whose only job is to find the flaw.

MOMUS is the OFFENSIVE counterpart to ARGUS (the defensive WARDEN firewall). It continuously
runs SAFE, read-only adversarial probes against the ecosystem's OWN declared contracts — oracle
free-tier ceilings, receipt signatures, escrow edge cases, prompt-injection surfaces — and
emits signed findings. Crucially, MOMUS finds and signs but is *structurally unable to pay
itself*: the bounty treasury is a separate role with its own key, and no payout is released
without an independent verifier. See momus.economics for why that separation is the whole point.
"""

__version__ = "0.1.0"

# Redeploy smoke-check: this comment exists only to prove that shipping a change does not
# regenerate the scanner key or lose the findings corpus (both live in a persistent volume).
