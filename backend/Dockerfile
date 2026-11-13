FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY sandbox_files ./sandbox_files
ENV MCP_SENTINEL_DATA_DIR=/data \
    MCP_SENTINEL_CORS_ORIGINS=http://localhost:5173,http://localhost:8080
VOLUME ["/data"]
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
