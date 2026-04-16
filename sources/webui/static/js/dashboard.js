/*
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * Dashboard JavaScript for i.MX DDoS Blocker
 */

// Global chart instances
let cpuChart, ramChart, networkChart;

// Data arrays for charts (last 10 data points)
let cpuData = [];
let ramData = [];
let networkRxData = [];
let networkTxData = [];
let timeLabels = [];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    fetchStats();
    setInterval(fetchStats, 1000); // Update every 1 second
});

// Initialize ECharts
function initializeCharts() {
    // CPU Chart
    cpuChart = echarts.init(document.getElementById('cpu-chart'));
    const cpuOption = {
        color: '#fcb316',
        backgroundColor: 'rgba(0,0,0,0)',
        tooltip: {
            trigger: 'axis'
        },
        legend: {
            data: ['CPU'],
            textStyle: {
                color: '#333',
                fontSize: 10
            },
            bottom: 0
        },
        grid: {
            top: '10%',
            bottom: '15%',
            left: '10%',
            right: '10%'
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: timeLabels,
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        yAxis: {
            type: 'value',
            min: 0,
            max: 100,
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        series: [{
            name: 'CPU',
            data: cpuData,
            type: 'line',
            smooth: true,
            areaStyle: {
                color: {
                    type: 'linear',
                    x: 0,
                    y: 0,
                    x2: 0,
                    y2: 1,
                    colorStops: [{
                        offset: 0,
                        color: '#fcb316'
                    }, {
                        offset: 1,
                        color: 'rgba(252, 179, 22, 0.1)'
                    }],
                    global: false
                }
            },
            lineStyle: {
                width: 2
            },
            itemStyle: {
                show: false
            }
        }]
    };
    cpuChart.setOption(cpuOption);

    // RAM Chart
    ramChart = echarts.init(document.getElementById('ram-chart'));
    const ramOption = {
        color: '#4CAF50',
        backgroundColor: 'rgba(0,0,0,0)',
        tooltip: {
            trigger: 'axis'
        },
        legend: {
            data: ['RAM'],
            textStyle: {
                color: '#333',
                fontSize: 10
            },
            bottom: 0
        },
        grid: {
            top: '10%',
            bottom: '15%',
            left: '10%',
            right: '10%'
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: timeLabels,
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        yAxis: {
            type: 'value',
            min: 0,
            max: 100,
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        series: [{
            name: 'RAM',
            data: ramData,
            type: 'line',
            smooth: true,
            areaStyle: {
                color: {
                    type: 'linear',
                    x: 0,
                    y: 0,
                    x2: 0,
                    y2: 1,
                    colorStops: [{
                        offset: 0,
                        color: '#4CAF50'
                    }, {
                        offset: 1,
                        color: 'rgba(76, 175, 80, 0.1)'
                    }],
                    global: false
                }
            },
            lineStyle: {
                width: 2
            },
            itemStyle: {
                show: false
            }
        }]
    };
    ramChart.setOption(ramOption);

    // Network Chart
    networkChart = echarts.init(document.getElementById('network-chart'));
    const networkOption = {
        color: ['#2196F3', '#FF5722'],
        backgroundColor: 'rgba(0,0,0,0)',
        tooltip: {
            trigger: 'axis'
        },
        legend: {
            data: ['RX', 'TX'],
            textStyle: {
                color: '#333',
                fontSize: 10
            },
            bottom: 0
        },
        grid: {
            top: '10%',
            bottom: '15%',
            left: '10%',
            right: '10%'
        },
        xAxis: {
            type: 'category',
            boundaryGap: false,
            data: timeLabels,
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        yAxis: {
            type: 'value',
            axisLabel: { show: false },
            axisLine: { show: false },
            splitLine: { show: false }
        },
        series: [
            {
                name: 'RX',
                data: networkRxData,
                type: 'line',
                smooth: true,
                lineStyle: {
                    width: 2
                },
                itemStyle: {
                    show: false
                }
            },
            {
                name: 'TX',
                data: networkTxData,
                type: 'line',
                smooth: true,
                lineStyle: {
                    width: 2
                },
                itemStyle: {
                    show: false
                }
            }
        ]
    };
    networkChart.setOption(networkOption);

    // Handle window resize
    window.addEventListener('resize', function() {
        cpuChart.resize();
        ramChart.resize();
        networkChart.resize();
    });
}

// Fetch statistics from API
function fetchStats() {
    const url = '/api/stats';
    
    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            updateDashboard(data);
            updateStatus();
        })
        .catch(error => {
            console.error('Fetch error:', error);
            document.getElementById('status-text').textContent = 
                'Error: ' + error.message;
        });
}

// Update dashboard with new data
function updateDashboard(data) {
    // Update XDP statistics
    document.getElementById('xdp-rx').textContent = formatNumber(data.xdp_rx_packets);
    document.getElementById('xdp-pass').textContent = formatNumber(data.xdp_pass_packets);
    document.getElementById('xdp-drop').textContent = formatNumber(data.xdp_drop_packets);
    document.getElementById('xdp-submit').textContent = formatNumber(data.xdp_submit_packets);

    // Update system resources
    document.getElementById('cpu-percent').textContent = data.cpu_percent.toFixed(1) + '%';
    document.getElementById('ram-percent').textContent = data.ram_percent.toFixed(1) + '%';
    document.getElementById('ram-used').textContent = data.ram_used_mb + ' MB';
    document.getElementById('ram-total').textContent = data.ram_total_mb + ' MB';

        // Update attacker IP list
    document.getElementById('attacker-count').textContent = data.blacklist_count || 0;
    document.getElementById('attacker-updates').textContent = data.blacklist_updates || 0;

    // Update attacker IPs
    updateAttackerIps(data.blacklist_ips || []);

    // Update network statistics
    const netRxMB = (data.net_rx_bytes / (1024 * 1024)).toFixed(1);
    const netTxMB = (data.net_tx_bytes / (1024 * 1024)).toFixed(1);
    document.getElementById('net-rx').textContent = netRxMB + ' MB';
    document.getElementById('net-tx').textContent = netTxMB + ' MB';
    document.getElementById('net-rx-packets').textContent = formatNumber(data.net_rx_packets || 0);
    document.getElementById('net-tx-packets').textContent = formatNumber(data.net_tx_packets || 0);

    // Update charts
    updateCharts(data);
}

// Update attacker IP list
function updateAttackerIps(ips) {
    const container = document.getElementById('attacker-ips-list');
    container.innerHTML = '';

    if (ips.length === 0) {
        container.innerHTML = '<div class="attacker-ip-item">No blocked IPs</div>';
        return;
    }

    ips.forEach(ip => {
        const item = document.createElement('div');
        item.className = 'attacker-ip-item';
        item.textContent = ip;
        container.appendChild(item);
    });
}

// Placeholder for XDP connections (to be implemented)
function updateXdpConnections(connections) {
    const container = document.getElementById('xdp-connections-list');
    container.innerHTML = '';

    if (connections.length === 0) {
        container.innerHTML = '<div class="xdp-connection-item">Connection table placeholder</div>';
        return;
    }

    connections.forEach(conn => {
        const item = document.createElement('div');
        item.className = 'xdp-connection-item';
        item.textContent = conn;
        container.appendChild(item);
    });
}

// Update charts with new data
function updateCharts(data) {
    const now = new Date();
    const timeLabel = now.getHours() + ':' + 
                     String(now.getMinutes()).padStart(2, '0') + ':' + 
                     String(now.getSeconds()).padStart(2, '0');

    // Add new data point
    timeLabels.push(timeLabel);
    cpuData.push(data.cpu_percent || 0);
    ramData.push(data.ram_percent || 0);
    networkRxData.push(data.net_rx_packets || 0);
    networkTxData.push(data.net_tx_packets || 0);

    // Keep only last 10 data points
    if (timeLabels.length > 10) {
        timeLabels.shift();
        cpuData.shift();
        ramData.shift();
        networkRxData.shift();
        networkTxData.shift();
    }

    // Update charts
    cpuChart.setOption({
        xAxis: { data: timeLabels },
        series: [{ data: cpuData }]
    });

    ramChart.setOption({
        xAxis: { data: timeLabels },
        series: [{ data: ramData }]
    });

    networkChart.setOption({
        xAxis: { data: timeLabels },
        series: [
            { data: networkRxData },
            { data: networkTxData }
        ]
    });
}

// Update status bar
function updateStatus() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    document.getElementById('status-text').textContent = 
        'Last Update: ' + timeString;
}

// Format large numbers
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// Control packets_controller and ml_detector
function controlService(action) {
    const statusEl = document.getElementById('control-status');
    statusEl.textContent = action + '...';
    fetch('/api/control/' + action, { method: 'POST' })
        .then(r => r.json())
        .then(data => { statusEl.textContent = data.message || data.error || ''; })
        .catch(e => { statusEl.textContent = 'Error: ' + e.message; });
}