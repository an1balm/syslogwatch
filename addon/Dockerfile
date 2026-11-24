ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM}

# Sin dependencias: todo es biblioteca estándar de Python.
WORKDIR /app
COPY app/ /app/

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8099
CMD ["python3", "-m", "syslogwatch.addon_main"]
