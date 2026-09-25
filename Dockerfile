# MOMUS backend — adversarial-audit satellite (AIMarket v2 surface + red-team engine).
# Build from the MONOREPO ROOT so oracle-core is in context:
#     docker build -f momus/Dockerfile -t momus-backend .
FROM python:3.11-slim
WORKDIR /app

COPY oracles/core /app/core
COPY momus /app/momus
# The protocol's OWN conformance reference — a second implementation of the canonical forms,
# written for the spec rather than copied from oracle_core. The verifier cross-checks the
# probe's answer against it, because a probe and its replay share one implementation and
# therefore share its mistakes: `manifest_canonical` has eight copies in this tree, and a
# probe computing the wrong one would fail every CORRECT signature, confidently, twice.
COPY aimarket-protocol/conformance /app/protocol-conformance

RUN pip install --no-cache-dir -e "/app/core[pqc]" -e '/app/momus[postgres]'

EXPOSE 9400
CMD ["python", "-m", "momus.main"]
