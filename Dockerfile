FROM python:3.11-slim
LABEL org="Sideways 8 Creations"
WORKDIR /app
RUN addgroup --system s8c88 && adduser --system --ingroup s8c88 s8c88
COPY --chown=s8c88:s8c88 requirements.txt requirements.txt 2>/dev/null || true
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || pip install --no-cache-dir scapy
COPY --chown=s8c88:s8c88 sniffdog.py .
USER s8c88
ENTRYPOINT ["python", "sniffdog.py"]
CMD ["--help"]
# --cap-add=NET_ADMIN or --network=host required at runtime
