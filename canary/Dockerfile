# MOMUS canary — a deliberately non-conforming fixture, so the detection pipeline can be seen to
# fire against a REAL contract violation. See momus/canary/README.md for why this exists and why
# the finding it produces is genuine while the target is not a real service.
# Build from the MONOREPO ROOT:  docker build -f momus/canary/Dockerfile -t momus-canary .
FROM python:3.11-slim
WORKDIR /app

COPY momus/canary /app/canary

RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30"

EXPOSE 9450
CMD ["python", "-m", "canary.canary"]
