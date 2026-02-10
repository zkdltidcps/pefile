#!/bin/bash

# 無限循環抓取腳本
# 建議配合 screen 或 nohup 使用

while true
do
    echo "=== Starting New Crawl Cycle: $(date) ==="
    
    echo "[1/3] Running GitHub Crawler..."
    docker-compose run crawler python scripts/crawler_github.py
    
    echo "[2/3] Running Chocolatey Crawler..."
    docker-compose run crawler python scripts/crawler_choco.py
    
    echo "[3/3] Running PortableApps Crawler..."
    docker-compose run crawler python scripts/crawler_portable.py
    
    echo "=== Cycle Finished. Sleeping for 1 hour... ==="
    sleep 3600
done
