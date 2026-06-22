FROM python:3.12-slim AS base

LABEL maintainer="arkanzasfeziii"
LABEL description="BlackForge — CI/CD & Supply Chain Attack Framework"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY blackforge/ blackforge/

HEALTHCHECK --interval=60s --timeout=5s \
    CMD python -c "from blackforge import __version__; print(__version__)" || exit 1

ENTRYPOINT ["python", "-m", "blackforge"]
CMD ["--help"]
