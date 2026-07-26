FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scan.py detection.py ./
# Vendored analyzer — regenerate with ./sync_analyzer.sh
COPY code_analysis/ ./code_analysis/

ENTRYPOINT ["python", "/app/scan.py"]
