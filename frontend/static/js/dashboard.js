async function loadDashboardData() {
    const response = await fetch('/api/traffic_stats');
    const data = await response.json();
    renderCharts(data);
    loadAlerts();
}

async function loadAlerts() {
    const response = await fetch('/api/threat_alerts');
    const data = await response.json();
    const container = document.getElementById('alert-cards');
    container.innerHTML = '';
    data.alerts.forEach(alert => {
        const card = document.createElement('div');
        card.className = 'alert-card';
        card.innerHTML = `
            <h4>${alert.anomaly ? 'Threat Detected' : 'Normal Traffic'}</h4>
            <p>Score: ${alert.score.toFixed(3)}</p>
            <small>${new Date(alert.timestamp).toLocaleString()}</small>
        `;
        container.appendChild(card);
    });
}

function renderCharts(data) {
    const volumeCtx = document.getElementById('volumeChart').getContext('2d');
    const alertCtx = document.getElementById('alertChart').getContext('2d');

    new Chart(volumeCtx, {
        type: 'line',
        data: {
            labels: data.message_volume.map(item => `Day ${item.day}`),
            datasets: [{
                label: 'Messages',
                data: data.message_volume.map(item => item.count),
                borderColor: '#8ef5ff',
                backgroundColor: 'rgba(142,245,255,0.15)',
                tension: 0.3,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: true } },
            scales: { y: { beginAtZero: true } }
        }
    });

    new Chart(alertCtx, {
        type: 'bar',
        data: {
            labels: data.alert_history.map(entry => new Date(entry.timestamp).toLocaleTimeString()),
            datasets: [{
                label: 'Threat Score',
                data: data.alert_history.map(entry => entry.score),
                backgroundColor: '#ff6b6b',
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } }
        }
    });
}

loadDashboardData();
