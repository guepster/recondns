FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
ENV PYTHONPATH=/app/src
ENTRYPOINT ["python", "-m", "recondns.cli"]
