FROM python:3.11-slim

# Install nmap system package
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
