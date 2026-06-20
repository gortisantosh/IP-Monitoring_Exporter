FROM python:3.12-slim

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY exporter.py .
COPY ip-engineer-mapping.json .

# Run exporter
CMD ["python", "exporter.py"]
