FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml .
COPY smart_token_prod ./smart_token_prod
COPY api ./api
# Install local package (no git). API deps without git+ URL.
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir -r api/requirements.txt
RUN useradd --create-home --uid 10001 appuser
USER appuser
EXPOSE 8000
# Render sets PORT; default 8000 for local docker
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
