#!/bin/bash

# 無限循環抓取腳本
# 建議配合 screen 或 nohup 使用

# 計數器，用來控制 PortableApps 的執行頻率
counter=0

while true
do
    echo "=== Starting New Crawl Cycle: $(date) ==="
    
    echo "[1/3] Running GitHub Crawler (High Priority)..."
    docker-compose run --rm crawler python scripts/crawler_github.py
    
    echo "[2/3] Running Chocolatey Crawler (High Priority)..."
    docker-compose run --rm crawler python scripts/crawler_choco.py
    
    # 每一輪 counter + 1，累積到 5 才跑一次 PortableApps
    counter=$((counter + 1))
    
    if [ $counter -ge 5 ]; then
        echo "[3/3] Running PortableApps Crawler (Low Priority, Large Files)..."
        docker-compose run --rm crawler python scripts/crawler_portable.py
        counter=0 # 重置計數器
    else
        echo "[3/3] Skipping PortableApps this round (Frequency: $counter/5)"
    fi
    
    echo "=== Cycle Finished. Sleeping for 5 minutes... ==="
    sleep 300
done
