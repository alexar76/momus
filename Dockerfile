# MOMUS backend — adversarial-audit satellite (AIMarket v2 surface + red-team engine).
# Build from the MONOREPO ROOT so oracle-core is in context:
#     docker build -f momus/Dockerfile -t momus-backend .
FROM python:3.11-slim
WORKDIR /app

COPY oracles/core /app/core
COPY momus /app/momus

RUN pip install --no-cache-dir -e /app/core -e /app/momus

EXPOSE 9400
CMD ["python", "-m", "momus.main"]
