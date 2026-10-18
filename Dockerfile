FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the application code, never key files from the build context.
COPY main.py client.py server.py attacker.py networkservice.py networkstack.py protocol.py ./
COPY RSA ./RSA
COPY GCM ./GCM
COPY diffieHellman ./diffieHellman

# Key files are written to the working directory, so it must be writable by the app user.
RUN useradd --create-home --uid 10001 chat \
    && mkdir /data \
    && chown chat:chat /data
USER chat
WORKDIR /data

ENTRYPOINT ["python", "/app/main.py"]
CMD ["server", "0.0.0.0", "8000"]
