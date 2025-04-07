// Modify your dashboard.js file to load data progressively
document.addEventListener('DOMContentLoaded', function() {
    // Load critical data immediately
    loadSummaryData();
    
    // Load charts with a slight delay
    setTimeout(loadChartData, 100);
    
    // Load full table data last
    setTimeout(loadAlertsTable, 200);
});

function loadSummaryData() {
    fetch('/api/alerts/summary')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalAlerts').textContent = data.total_alerts;
            document.getElementById('highSeverityAlerts').textContent = data.high_severity_alerts;
            document.getElementById('recentAlerts').textContent = data.recent_alerts;
            document.getElementById('monitoringStatus').innerHTML = '<i class="fas fa-check-circle"></i> Active';
        });
}

function loadChartData() {
    // Load charts...
}