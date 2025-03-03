#!/bin/bash

# output file name
LOG_FILE="system_usage.csv"

# write CSV header
echo "timestamp,cpu_usage(%),mem_usage(MB)" > "$LOG_FILE"

prev_total=0
prev_idle=0

while true; do
    # Get timestamp (ns)
    timestamp=$(date +"%Y-%m-%dT%T.%N")

    # CPU usage ratio
    read -r cpu user nice system idle iowait irq softirq steal guest guest_nice <<< "$(grep '^cpu ' /proc/stat)"
    
    total=$((user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice))
    current_idle=$((idle + iowait))  # include iowait

    # Calculate CPU%
    if [[ $prev_total -ne 0 ]]; then
        total_diff=$((total - prev_total))
        idle_diff=$((current_idle - prev_idle))
        cpu_usage=$(( (100 * (total_diff - idle_diff)) / total_diff ))
    else
        cpu_usage=0
    fi

    # Update previous
    prev_total=$total
    prev_idle=$current_idle

    # memory usage
    mem_usage=$(free -m | awk '/Mem:/ {print $3}')  # MB

    # Log
    echo "$timestamp,$cpu_usage,$mem_usage" >> "$LOG_FILE"

    # interval 0.5s
    sleep 0.5
done