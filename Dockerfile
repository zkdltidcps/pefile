FROM python:3.10-slim

WORKDIR /app

# 安裝基本工具與簽名校驗工具
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    osslsigncode \
    && rm -rf /var/lib/apt/lists/*

# 複製需求檔並安裝
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 複製腳本與設定
COPY scripts/ ./scripts/
COPY config.yaml .

# 預設執行爬蟲 (可透過 docker-compose override)
CMD ["python", "scripts/crawler_github.py"]
