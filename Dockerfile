FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src/ /app/src/

WORKDIR /app/src

EXPOSE 8501

CMD ["streamlit", "run", "dashboard.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
