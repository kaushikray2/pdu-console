FROM python:3.12-alpine
WORKDIR /app
COPY app/server.py /app/server.py
COPY static/ /app/static/
RUN adduser -D -H pdu && mkdir -p /app/data && chown -R pdu /app
USER pdu
ENV PORT=8080 PDU_DATA_DIR=/app/data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1
CMD ["python3", "server.py"]
