#!/bin/bash

# 統計已搜集的檔案數量
echo "=== PE Collection Progress Report ==="
echo "Date: $(date)"
echo ""

# GitHub
count_github=$(find benign_pe/github_release -type f | wc -l)
size_github=$(du -sh benign_pe/github_release 2>/dev/null | cut -f1)
echo "GitHub Releases:  $count_github files ($size_github)"

# Chocolatey
count_choco=$(find benign_pe/chocolatey -type f | wc -l)
size_choco=$(du -sh benign_pe/chocolatey 2>/dev/null | cut -f1)
echo "Chocolatey Apps: $count_choco files ($size_choco)"

# PortableApps
count_portable=$(find benign_pe/portableapps -type f | wc -l)
size_portable=$(du -sh benign_pe/portableapps 2>/dev/null | cut -f1)
echo "PortableApps:   $count_portable files ($size_portable)"

echo "--------------------------------"
total=$((count_github + count_choco + count_portable))
total_size=$(du -sh benign_pe/ 2>/dev/null | cut -f1)
echo "Total Benign PE: $total files ($total_size)"

# 計算目標達成率 (10萬個)
target=100000
percent=$(echo "scale=2; $total * 100 / $target" | bc)
echo "Goal Progress:   $percent% ($total / $target)"
echo ""
