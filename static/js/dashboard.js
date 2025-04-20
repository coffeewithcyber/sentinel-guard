document.addEventListener('DOMContentLoaded', function() {
    // Connect to SocketIO for real-time updates
    const socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);
    
    // Elements for real-time updates
    const alertsTableBody = document.getElementById('alerts-table-body');
    const logsTableBody = document.getElementById('logs-table-body');
    const alertCounter = document.getElementById('alert-counter');
    const criticalCounter = document.getElementById('critical-count');
    const highCounter = document.getElementById('high-count');
    const mediumCounter = document.getElementById('medium-count');
    const lowCounter = document.getElementById('low-count');
    const infoCounter = document.getElementById('info-count');
    
    // Charts
    let trafficChart = null;
    let alertSeverityChart = null;
    let trafficTypeChart = null;
    
    // Initialize DataTables
    const alertsTable = $('#alerts-table').DataTable({
        order: [[0, 'desc']],
        responsive: true,
        pageLength: 10,
        language: {
            search: "_INPUT_",
            searchPlaceholder: "Search alerts"
        }
    });
    
    const logsTable = $('#logs-table').DataTable({
        order: [[0, 'desc']],
        responsive: true,
        pageLength: 25,
        language: {
            search: "_INPUT_",
            searchPlaceholder: "Search logs"
        }
    });
    
    // Handle new alerts from SocketIO
    socket.on('new_alert', function(alert) {
        // Add to alerts table
        const newRow = [
            alert.id,
            formatTimestamp(alert.timestamp),
            createSeverityBadge(alert.severity),
            alert.source_ip,
            alert.destination_ip,
            alert.message,
            '<button class="btn btn-sm btn-primary acknowledge-btn" data-id="' + alert.id + '">Acknowledge</button>'
        ];
        
        // Add to DataTable and redraw
        alertsTable.row.add(newRow).draw(false);
        
        // Update counters
        updateAlertCounter(alert.severity);
        
        // Play sound for critical and high alerts
        if (alert.severity === 'critical' || alert.severity === 'high') {
            playAlertSound();
        }
        
        // Show browser notification if enabled
        showBrowserNotification(alert);
        
        // Update charts
        updateCharts();
    });
    
    // Handle new log entries from SocketIO
    socket.on('new_log', function(log) {
        // Add to logs table
        const newRow = [
            log.id,
            formatTimestamp(log.timestamp),
            createSeverityBadge(log.severity),
            log.protocol,
            log.source_ip,
            log.destination_ip,
            log.port || '-',
            log.data_size || '-',
            log.message
        ];
        
        // Add to DataTable and redraw
        logsTable.row.add(newRow).draw(false);
        
        // Update the counter for the appropriate severity
        updateLogCounter(log.severity);
        
        // Update charts
        updateCharts();
    });
    
    // Handle info counter updates
    socket.on('update_info_counter', function() {
        // Update the info counter
        infoCounter.textContent = (parseInt(infoCounter.textContent) || 0) + 1;
        
        // Update total alert counter
        alertCounter.textContent = (parseInt(alertCounter.textContent) || 0) + 1;
        
        // Update the severity chart for info alerts too
        if (alertSeverityChart && alertSeverityChart.data && alertSeverityChart.data.datasets) {
            alertSeverityChart.data.datasets[0].data[4] += 1; // Index 4 is for "Info"
            alertSeverityChart.update();
        }
    });
    
    // Initialize charts when page loads
    initCharts();
    
    // Fetch initial data
    fetchAlertSummary();
    fetchRecentTraffic();
    
    // Set up acknowledge button click handler
    $('#alerts-table').on('click', '.acknowledge-btn', function() {
        const alertId = $(this).data('id');
        acknowledgeAlert(alertId);
    });
    
    // Update charts every minute
    setInterval(updateCharts, 60000);
    
    // Functions
    
    function initCharts() {
        // Traffic over time chart
        const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
        trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Traffic Volume',
                    data: [],
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    borderWidth: 1,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Alert severity distribution chart
        const severityCtx = document.getElementById('alert-severity-chart').getContext('2d');
        alertSeverityChart = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#7E1431', // dark red
                        '#E12D39', // light red
                        '#F68E1F', // orange
                        '#4A71B2', // blue
                        '#58C1E8'  // sky blue
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
        
        // Traffic type distribution chart
        const trafficTypeCtx = document.getElementById('traffic-type-chart').getContext('2d');
        trafficTypeChart = new Chart(trafficTypeCtx, {
            type: 'bar',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
                datasets: [{
                    label: 'Protocol Distribution',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(169, 169, 169, 0.7)'
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(169, 169, 169, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    function updateCharts() {
        fetchAlertSummary();
        fetchRecentTraffic();
    }
    
    function fetchAlertSummary() {
        fetch('/api/alert_summary')
            .then(response => response.json())
            .then(data => {
                // Update the severity chart
                alertSeverityChart.data.datasets[0].data = [
                    data.critical,
                    data.high,
                    data.medium,
                    data.low,
                    data.info
                ];
                alertSeverityChart.update();
                
                // Update counters
                criticalCounter.textContent = data.critical;
                highCounter.textContent = data.high;
                mediumCounter.textContent = data.medium;
                lowCounter.textContent = data.low;
                infoCounter.textContent = data.info;
                
                // Update total counter
                const total = data.critical + data.high + data.medium + data.low + data.info;
                alertCounter.textContent = total;
            })
            .catch(error => console.error('Error fetching alert summary:', error));
    }
    
    function fetchRecentTraffic() {
        fetch('/api/logs?limit=100')
            .then(response => response.json())
            .then(logs => {
                updateTrafficCharts(logs);
            })
            .catch(error => console.error('Error fetching recent traffic:', error));
    }
    
    function updateTrafficCharts(logs) {
        // Process logs for traffic over time chart
        const timePoints = {};
        const protocolCounts = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'Other': 0
        };
        
        logs.forEach(log => {
            // Get hour of log entry for the traffic over time chart
            const timestamp = new Date(log.timestamp);
            const hour = timestamp.getHours();
            const timeKey = `${hour}:00`;
            
            // Count entries per hour
            if (!timePoints[timeKey]) {
                timePoints[timeKey] = 0;
            }
            timePoints[timeKey]++;
            
            // Count by protocol
            if (log.protocol) {
                if (protocolCounts.hasOwnProperty(log.protocol)) {
                    protocolCounts[log.protocol]++;
                } else {
                    protocolCounts['Other']++;
                }
            } else {
                protocolCounts['Other']++;
            }
        });
        
        // Update traffic over time chart
        const sortedTimeKeys = Object.keys(timePoints).sort((a, b) => {
            return parseInt(a) - parseInt(b);
        });
        
        trafficChart.data.labels = sortedTimeKeys;
        trafficChart.data.datasets[0].data = sortedTimeKeys.map(key => timePoints[key]);
        trafficChart.update();
        
        // Update traffic type chart
        trafficTypeChart.data.datasets[0].data = [
            protocolCounts['TCP'],
            protocolCounts['UDP'],
            protocolCounts['ICMP'],
            protocolCounts['ARP'],
            protocolCounts['Other']
        ];
        trafficTypeChart.update();
    }
    
    function updateAlertCounter(severity) {
        // Increment the correct counter based on severity
        let counter;
        switch (severity) {
            case 'critical':
                counter = criticalCounter;
                break;
            case 'high':
                counter = highCounter;
                break;
            case 'medium':
                counter = mediumCounter;
                break;
            case 'low':
                counter = lowCounter;
                break;
            case 'info':
                counter = infoCounter;
                break;
            default:
                return;
        }
        
        counter.textContent = (parseInt(counter.textContent) || 0) + 1;
        
        // Update total alert counter
        alertCounter.textContent = (parseInt(alertCounter.textContent) || 0) + 1;
    }
    
    function updateLogCounter(severity) {
        // Also update the corresponding counter for log entries
        let counter;
        switch (severity) {
            case 'critical':
                counter = criticalCounter;
                break;
            case 'high':
                counter = highCounter;
                break;
            case 'medium':
                counter = mediumCounter;
                break;
            case 'low':
                counter = lowCounter;
                break;
            case 'info':
                counter = infoCounter;
                break;
            default:
                return;
        }
        
        counter.textContent = (parseInt(counter.textContent) || 0) + 1;
        
        // Update total counter
        alertCounter.textContent = (parseInt(alertCounter.textContent) || 0) + 1;
        
        // Update the chart as well
        if (alertSeverityChart && alertSeverityChart.data && alertSeverityChart.data.datasets) {
            let index;
            switch (severity) {
                case 'critical': index = 0; break;
                case 'high': index = 1; break;
                case 'medium': index = 2; break;
                case 'low': index = 3; break;
                case 'info': index = 4; break;
                default: return;
            }
            
            alertSeverityChart.data.datasets[0].data[index] += 1;
            alertSeverityChart.update();
        }
    }
    
    function formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }
    
    function createSeverityBadge(severity) {
        let badgeClass = '';
        switch (severity) {
            case 'critical':
                badgeClass = 'bg-danger text-white fw-bold';
                break;
            case 'high':
                badgeClass = 'bg-danger text-white';
                break;
            case 'medium':
                badgeClass = 'bg-warning';
                break;
            case 'low':
                badgeClass = 'bg-primary text-white';
                break;
            case 'info':
                badgeClass = 'bg-info';
                break;
            default:
                badgeClass = 'bg-secondary';
        }
        
        return `<span class="badge ${badgeClass}">${severity.toUpperCase()}</span>`;
    }
    
    function playAlertSound() {
        // Implement sound alert if needed
        // You can use the Audio API to play a sound file
        try {
            const audio = new Audio('/static/sounds/alert.mp3');
            audio.play();
        } catch (e) {
            console.log('Sound could not be played');
        }
    }
    
    function showBrowserNotification(alert) {
        // Show browser notification if permission is granted
        if (Notification.permission === 'granted') {
            const notification = new Notification('Sentinel-Guard Alert', {
                body: `${alert.severity.toUpperCase()}: ${alert.message}`,
                icon: '/static/svg/logo.svg'
            });
            
            // Close the notification after 5 seconds
            setTimeout(() => {
                notification.close();
            }, 5000);
        }
        // Request permission if not asked before
        else if (Notification.permission !== 'denied') {
            Notification.requestPermission();
        }
    }
    
    function acknowledgeAlert(alertId) {
        fetch(`/api/alerts/${alertId}/acknowledge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                // Update the UI to reflect the acknowledgment
                const row = alertsTable.row(function(idx, data, node) {
                    return data[0] == alertId;
                });
                
                if (row.length) {
                    const rowData = row.data();
                    rowData[6] = '<span class="badge bg-success">Acknowledged</span>';
                    row.data(rowData).draw(false);
                }
            }
        })
        .catch(error => console.error('Error acknowledging alert:', error));
    }
});
