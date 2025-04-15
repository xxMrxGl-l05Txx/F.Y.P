// dashboard.js - For real-time dashboard updates

// Initialize socket connection for real-time updates
let socket;

document.addEventListener('DOMContentLoaded', function() {
    // Load critical data immediately
    loadSummaryData();
    
    // Load charts with a slight delay
    setTimeout(loadChartData, 100);
    
    // Load full table data last
    setTimeout(loadAlertsTable, 200);
    
    // Initialize Socket.IO if available
    if (typeof io !== 'undefined') {
        socket = io();
        
        socket.on('connect', function() {
            console.log('Connected to server');
            
            // Update status indicator
            const statusIndicator = document.querySelector('.status-indicator');
            if (statusIndicator) {
                statusIndicator.classList.add('status-active');
                statusIndicator.innerHTML = '<i class="fas fa-circle"></i> Monitoring Active';
            }
            
            if (document.getElementById('monitoringStatus')) {
                document.getElementById('monitoringStatus').innerHTML = '<i class="fas fa-check-circle"></i> Active';
            }
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from server');
            
            // Update status indicator
            const statusIndicator = document.querySelector('.status-indicator');
            if (statusIndicator) {
                statusIndicator.classList.remove('status-active');
                statusIndicator.innerHTML = '<i class="fas fa-circle"></i> Monitoring Inactive';
            }
            
            if (document.getElementById('monitoringStatus')) {
                document.getElementById('monitoringStatus').innerHTML = '<i class="fas fa-exclamation-circle"></i> Inactive';
            }
        });
        
        // Listen for new alerts
        socket.on('new_alert', function(alertData) {
            console.log('New alert received', alertData);
            
            // Update alerts counter
            updateAlertCounters();
            
            // Add alert to the table if we're on the dashboard
            if (document.getElementById('alertsTable')) {
                addAlertToTable(alertData);
            }
            
            // Show notification
            showAlertNotification(alertData);
        });
        
        // Listen for system updates
        socket.on('system_update', function(systemData) {
            console.log('System update received', systemData);
            
            // Update system stats
            updateSystemStats(systemData);
        });
    }
    
    // Set up refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadSummaryData();
            loadChartData();
            loadAlertsTable();
        });
    }
});

function loadSummaryData() {
    fetch('/api/alerts/summary')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalAlerts').textContent = data.total_alerts;
            document.getElementById('highSeverityAlerts').textContent = data.high_severity_alerts;
            document.getElementById('recentAlerts').textContent = data.recent_alerts;
            document.getElementById('monitoringStatus').innerHTML = '<i class="fas fa-check-circle"></i> Active';
            
            // Get unique LOLBins count if available
            if (document.getElementById('uniqueLolbins')) {
                document.getElementById('uniqueLolbins').textContent = data.unique_lolbins || 0;
            }
        })
        .catch(error => {
            console.error('Error loading summary data:', error);
        });
        
    // Load system performance data
    fetch('/api/performance')
        .then(response => response.json())
        .then(data => {
            updateSystemStats(data);
        })
        .catch(error => {
            console.error('Error loading performance data:', error);
        });
}

function loadAlertsTable() {
    // Show loading spinner in table if it exists
    const alertsTable = document.getElementById('alertsTable');
    if (alertsTable) {
        alertsTable.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">
                    <div class="spinner-border spinner-border-sm text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    Loading...
                </td>
            </tr>
        `;
    }

    // Load recent alerts
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            if (alertsTable) {
                // Clear existing rows
                alertsTable.innerHTML = '';
                
                if (data.length === 0) {
                    alertsTable.innerHTML = `
                        <tr>
                            <td colspan="6" class="text-center">No alerts found</td>
                        </tr>
                    `;
                    return;
                }
                
                // Add recent alerts
                const recentAlerts = data.slice(0, 10); // Get most recent 10 alerts
                recentAlerts.forEach(alert => {
                    addAlertToTable(alert);
                });
            }
        })
        .catch(error => {
            console.error('Error loading alerts:', error);
            if (alertsTable) {
                alertsTable.innerHTML = `
                    <tr>
                        <td colspan="6" class="text-center text-danger">Error loading alerts</td>
                    </tr>
                `;
            }
        });
}

function loadChartData() {
    // Show loading indicators
    const loadingElements = document.querySelectorAll('.loading-overlay');
    loadingElements.forEach(el => { el.style.display = 'flex'; });
    
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            updateCharts(data);
            
            // Hide loading indicators
            loadingElements.forEach(el => { el.style.display = 'none'; });
        })
        .catch(error => {
            console.error('Error loading chart data:', error);
            
            // Hide loading indicators
            loadingElements.forEach(el => { el.style.display = 'none'; });
        });
}

// Update charts based on alert data
function updateCharts(alertsData) {
    // Only proceed if we have the charts initialized
    if (typeof alertsOverTimeChart === 'undefined' || 
        typeof severityChart === 'undefined' || 
        typeof lolbinsChart === 'undefined') {
        console.log('Charts not initialized yet');
        return;
    }

    // Update alerts over time chart
    updateAlertsOverTimeChart(alertsData);
    
    // Update severity distribution chart
    updateSeverityChart(alertsData);
    
    // Update LOLBins distribution chart
    updateLolbinsChart(alertsData);
}

// Update alerts over time chart
function updateAlertsOverTimeChart(data) {
    // Group alerts by date
    const dates = {};
    data.forEach(alert => {
        const date = alert.timestamp.split(' ')[0];
        dates[date] = (dates[date] || 0) + 1;
    });
    
    // Convert to arrays for Chart.js
    const sortedDates = Object.keys(dates).sort();
    const counts = sortedDates.map(date => dates[date]);
    
    // Update chart
    alertsOverTimeChart.data.labels = sortedDates;
    alertsOverTimeChart.data.datasets[0].data = counts;
    alertsOverTimeChart.update();
}

// Update severity distribution chart
function updateSeverityChart(data) {
    // Count alerts by severity
    const severityCounts = [0, 0, 0, 0, 0]; // Severity 1-5
    
    data.forEach(alert => {
        const severity = alert.severity;
        if (severity >= 1 && severity <= 5) {
            severityCounts[severity - 1]++;
        }
    });
    
    // Update chart
    severityChart.data.datasets[0].data = severityCounts;
    severityChart.update();
}

// Update LOLBins chart
function updateLolbinsChart(data) {
    // Count alerts by LOLBin
    const lolbinCounts = {};
    data.forEach(alert => {
        const process = alert.process_name;
        lolbinCounts[process] = (lolbinCounts[process] || 0) + 1;
    });
    
    // Sort by count (descending)
    const sortedLolbins = Object.entries(lolbinCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5); // Top 5
    
    // Update chart
    lolbinsChart.data.labels = sortedLolbins.map(item => item[0]);
    lolbinsChart.data.datasets[0].data = sortedLolbins.map(item => item[1]);
    lolbinsChart.update();
}

// Add an alert to the table
function addAlertToTable(alert) {
    const alertsTable = document.getElementById('alertsTable');
    if (!alertsTable) return;
    
    const tr = document.createElement('tr');
    tr.className = 'alert-row';
    
    // Severity
    const tdSeverity = document.createElement('td');
    const severityBadge = document.createElement('span');
    severityBadge.className = `severity-badge severity-${alert.severity}`;
    severityBadge.textContent = alert.severity;
    tdSeverity.appendChild(severityBadge);
    tr.appendChild(tdSeverity);
    
    // Timestamp
    const tdTime = document.createElement('td');
    tdTime.textContent = alert.timestamp;
    tr.appendChild(tdTime);
    
    // Rule
    const tdRule = document.createElement('td');
    tdRule.textContent = alert.rule_name;
    tr.appendChild(tdRule);
    
    // Process
    const tdProcess = document.createElement('td');
    tdProcess.textContent = alert.process_name;
    tr.appendChild(tdProcess);
    
    // User
    const tdUser = document.createElement('td');
    tdUser.textContent = alert.username;
    tr.appendChild(tdUser);
    
    // Actions
    const tdActions = document.createElement('td');
    
    // View button
    const viewBtn = document.createElement('button');
    viewBtn.className = 'btn btn-sm btn-outline-light me-1';
    viewBtn.innerHTML = '<i class="fas fa-eye"></i>';
    viewBtn.title = 'View Details';
    viewBtn.addEventListener('click', function() {
        showAlertDetails(alert);
    });
    
    // Ignore button
    const ignoreBtn = document.createElement('button');
    ignoreBtn.className = 'btn btn-sm btn-outline-danger';
    ignoreBtn.innerHTML = '<i class="fas fa-ban"></i>';
    ignoreBtn.title = 'Ignore Alert';
    
    tdActions.appendChild(viewBtn);
    tdActions.appendChild(ignoreBtn);
    tr.appendChild(tdActions);
    
    // Add row to table (prepend to show newest first)
    if (alertsTable.firstChild) {
        alertsTable.insertBefore(tr, alertsTable.firstChild);
    } else {
        alertsTable.appendChild(tr);
    }
    
    // If table has more than 10 rows, remove the oldest
    if (alertsTable.childElementCount > 10) {
        alertsTable.removeChild(alertsTable.lastChild);
    }
}

// Update alert counters
function updateAlertCounters() {
    fetch('/api/alerts/summary')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalAlerts').textContent = data.total_alerts;
            document.getElementById('highSeverityAlerts').textContent = data.high_severity_alerts;
            document.getElementById('recentAlerts').textContent = data.recent_alerts;
        })
        .catch(error => {
            console.error('Error updating alert counters:', error);
        });
}

// Show alert details in a modal or panel
function showAlertDetails(alert) {
    // This function would be implemented depending on how you want to display alert details
    // For example, it could populate a modal and show it
    console.log('Showing details for alert:', alert);
    
    // Example implementation assuming you have a modal with specific IDs
    if (document.getElementById('alertDetailModal')) {
        // Set modal content
        document.getElementById('detailRule').textContent = alert.rule_name;
        document.getElementById('detailSeverityText').textContent = getSeverityText(alert.severity);
        document.getElementById('detailTimestamp').textContent = alert.timestamp;
        document.getElementById('detailProcess').textContent = `${alert.process_name} (PID: ${alert.pid})`;
        document.getElementById('detailUser').textContent = alert.username;
        document.getElementById('detailCommand').textContent = alert.command_line || 'N/A';
        document.getElementById('detailDescription').textContent = alert.description;
        
        // Update severity badge
        const severityBadge = document.querySelector('#alertDetailModal .severity-badge');
        if (severityBadge) {
            severityBadge.className = `severity-badge severity-${alert.severity} me-2`;
            severityBadge.textContent = alert.severity;
        }
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
        modal.show();
    }
}

// Show a notification for new alerts
function showAlertNotification(alert) {
    // Check if the browser supports notifications
    if (!("Notification" in window)) {
        console.log("This browser does not support desktop notification");
        return;
    }
    
    // Check if we have permission
    if (Notification.permission === "granted") {
        createNotification(alert);
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(function (permission) {
            if (permission === "granted") {
                createNotification(alert);
            }
        });
    }
}

// Create a notification
function createNotification(alert) {
    const title = `Security Alert: ${alert.rule_name}`;
    const options = {
        body: `${alert.description}\nProcess: ${alert.process_name}\nSeverity: ${alert.severity}/5`,
        icon: '/static/img/alert-icon.png' // You would need to add this image
    };
    
    const notification = new Notification(title, options);
    
    notification.onclick = function() {
        window.focus();
        showAlertDetails(alert);
        this.close();
    };
    
    // Auto close after 5 seconds
    setTimeout(notification.close.bind(notification), 5000);
}

// Helper to get severity text
function getSeverityText(severity) {
    switch(parseInt(severity)) {
        case 1: return 'Low';
        case 2: return 'Medium-Low';
        case 3: return 'Medium';
        case 4: return 'Medium-High';
        case 5: return 'High';
        default: return 'Unknown';
    }
}

// Update system statistics
function updateSystemStats(data) {
    // Update CPU usage
    const cpuBar = document.querySelector('.progress-bar.bg-info');
    if (cpuBar) {
        const cpuPercent = data.system?.current_cpu_percent || 0;
        cpuBar.style.width = `${cpuPercent}%`;
        cpuBar.setAttribute('aria-valuenow', cpuPercent);
    }
    
    // Update memory usage
    const memBar = document.querySelector('.progress-bar.bg-warning');
    if (memBar) {
        const memPercent = data.system?.current_memory_percent || 0;
        memBar.style.width = `${memPercent}%`;
        memBar.setAttribute('aria-valuenow', memPercent);
    }
    
    // Update disk usage if available
    const diskBar = document.querySelector('.progress-bar.bg-success');
    if (diskBar && data.system?.disk_usage_percent) {
        const diskPercent = data.system.disk_usage_percent;
        diskBar.style.width = `${diskPercent}%`;
        diskBar.setAttribute('aria-valuenow', diskPercent);
    }
    
    // Update network usage if available
    const netBar = document.querySelector('.progress-bar.bg-primary');
    if (netBar && data.system?.network_usage_percent) {
        const netPercent = data.system.network_usage_percent;
        netBar.style.width = `${netPercent}%`;
        netBar.setAttribute('aria-valuenow', netPercent);
    }
}