FROM python:3.11-slim

LABEL org="Sideways 8 Creations"
LABEL description="SniffDog — Streaming pcap credential analyzer"
LABEL version="1.0.0"

WORKDIR /app

# Create non-root user
RUN addgroup --system s8c88 && adduser --system --ingroup s8c88 s8c88

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY sniffdog.py .

# Switch to non-root user
USER s8c88

# Note: at runtime you must add --cap-add=NET_ADMIN or --network=host
# to allow raw socket / packet capture operations

ENTRYPOINT ["python", "sniffdog.py"]
