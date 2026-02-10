#!/bin/bash

# 統計已搜集的檔案數量
echo "=== PE Collection Progress Report ==="
echo "Date: $(date)"
echo ""

# GitHub
count_github=$(find benign_pe/github_release -type f | wc -l)
echo "GitHub Releases:  $count_github files"

# Chocolatey
count_choco=$(find benign_pe/chocolatey -type f | wc -l)
echo "Chocolatey Apps: $count_choco files"

# PortableApps
count_portable=$(find benign_pe/portableapps -type f | wc -l)
echo "PortableApps:   $count_portable files"

echo "--------------------------------"
total=$((count_github + count_choco + count_portable))
echo "Total Benign PE: $total files"

# 計算目標達成率 (10萬個)
target=100000
percent=$(echo "scale=2; $total * 100 / $target" | bc)
echo "Goal Progress:   $percent% ($total / $target)"
echo ""
