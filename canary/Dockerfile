# MOMUS canary — a deliberately non-conforming fixture, so the detection pipeline can be seen to
# fire against a REAL contract violation. See momus/canary/README.md for why this exists and why
# the finding it produces is genuine while the target is not a real service.
# Build from the MONOREPO ROOT:  docker build -f momus/canary/Dockerfile -t momus-canary .
FROM python:3.11-slim
WORKDIR /app

COPY momus/canary /app/canary

# `cryptography` is here because a CONFORMING canary has to sign its manifest for real —
# the manifest_signature_integrity probe wants a signature that verifies, and there is no
# honest way to produce an Ed25519 signature without a signing library. What the image
# contains is an operator's decision; the remediation loop may fix code inside it but may
# never add a dependency of its own, so this line has to exist before a fix can.
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "cryptography>=42" \
                               "aimarket-oracle-core"
# aimarket-oracle-core ships the SAME manifest_canonical the verifier uses. Nobody should
# reimplement an interop contract from a description of it - that file even warns that a
# sixth field must follow the same day, which is exactly the promise a second copy cannot
# keep. Measured: given the contract in prose, every autonomous attempt signed its own
# plausible canonicalisation instead.

EXPOSE 9450
CMD ["python", "-m", "canary.canary"]
