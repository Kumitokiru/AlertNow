const socket = io('http://192.168.1.100:5000');
const alertContainer = document.getElementById('alert-container');

socket.on('new_alert', (data) => {
    const div = document.createElement('div');
    div.innerHTML = `
        <p><strong>Type:</strong> ${data.emergency_type}</p>
        <p><strong>Location:</strong> ${data.lat}, ${data.lon}</p>
        ${data.image ? `<img src="data:image/jpeg;base64,${data.image}" width="200"/>` : ''}
        <hr>
    `;
    alertContainer.prepend(div);
    updateCharts();
});

function updateCharts() {
    const role = window.location.pathname.includes('barangay') ? 'barangay' : 
                 window.location.pathname.includes('cdrrmo') ? 'cdrmo' : 
                 window.location.pathname.includes('pnp') ? 'pnp' : 'all';
    fetch(`/api/distribution?role=${role}`)
        .then(res => res.json())
        .then(dist => {
            const ctxDist = document.getElementById('distChart').getContext('2d');
            if (window.distChart) window.distChart.destroy();
            window.distChart = new Chart(ctxDist, {
                type: 'pie',
                data: {
                    labels: Object.keys(dist),
                    datasets: [{
                        data: Object.values(dist),
                        backgroundColor: ['red', 'orange', 'yellow', 'green', 'blue', 'purple']
                    }]
                }
            });
        });
    const ctxTrend = document.getElementById('trendChart')?.getContext('2d');
    if (ctxTrend && window.trendChart) window.trendChart.destroy();
    if (ctxTrend) {
        window.trendChart = new Chart(ctxTrend, {
            type: 'line',
            data: { labels: ['Jun 10', 'Jun 11', 'Jun 12'], datasets: [{ label: 'Incidents', data: [5, 8, 3], borderColor: 'blue', fill: false }] }
        });
    }
}

updateCharts();