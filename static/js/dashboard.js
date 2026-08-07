// ==========================================
// EXAMSHIELD - DASHBOARD MODULE SCRIPTS
// ==========================================
// Handles responsive side nav actions, Leaflet mapping markers,
// and ChartJS risk metrics visualization.

document.addEventListener("DOMContentLoaded", () => {
    // 1. MOBILE SIDEBAR TOGGLE
    const menuBtn = document.getElementById("mobile-menu-btn");
    const sidebar = document.getElementById("mysidenav");
    const icon = document.getElementById("menu-icon");

    if (menuBtn && sidebar && icon) {
        menuBtn.onclick = function () {
            sidebar.classList.toggle("active");
            
            if (sidebar.classList.contains("active")) {
                icon.classList.remove("fa-bars");
                icon.classList.add("fa-xmark");
            } else {
                icon.classList.remove("fa-xmark");
                icon.classList.add("fa-bars");
            }
        };
    }

    // 2. LEAFLET MAP INJECTION
    // Initializes the map on the '#map' element. Sets default center (Mumbai region)
    if (document.getElementById("map")) {
        const map = L.map('map').setView([19.0760, 72.8777], 9);

        // Load open street map tiles (Requires internet access in client browser)
        L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 18,
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        // Read dynamic centers array injected via global page variable EXAM_CENTERS_DATA
        if (typeof EXAM_CENTERS_DATA !== 'undefined' && Array.isArray(EXAM_CENTERS_DATA)) {
            EXAM_CENTERS_DATA.forEach(center => {
                let color;
                
                // Color scale representing center health:
                // >= 95 : Secure (Green)
                // >= 80 : Watchlist (Orange)
                // < 80  : Warning (Red)
                if (center.score >= 95) {
                    color = "#22c55e"; // Green
                } else if (center.score >= 80) {
                    color = "#fbbf24"; // Orange/Yellow
                } else {
                    color = "#ef4444"; // Red
                }

                // Append circle marker onto Leaflet map
                const marker = L.circleMarker([center.lat, center.lng], {
                    radius: 8,
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.8,
                    weight: 2
                }).addTo(map);

                // Add descriptive mouse tooltip/popup showing status and security score
                marker.bindPopup(`
                    <div style="font-family:'Poppins',sans-serif;">
                        <h4 style="margin:0 0 5px; color:#2563EB;">${center.name}</h4>
                        <p style="margin:2px 0; font-size:12px; color:#64748B;">Location: <b>${center.city}</b></p>
                        <p style="margin:2px 0; font-size:12px;">Integrity Index: <b style="color:${color};">${center.score}%</b></p>
                        <p style="margin:2px 0; font-size:12px;">Status: <b style="color:${center.status === 'Online' ? '#22c55e' : '#ef4444'};">${center.status}</b></p>
                    </div>
                `);
            });
        }
    }

    // 3. CHARTJS BAR CHART GENERATION
    // Renders the risk levels graph comparing centers
    const ctx = document.getElementById('riskChart');
    if (ctx) {
        // Read labels and risk parameters dynamically if present, else fall back to default seeds
        let labels = ["Mumbai", "Navi Mumbai", "Thane", "Pune", "Delhi"];
        let riskScores = [15, 45, 75, 20, 50]; // default static fallback

       if (typeof EXAM_CENTERS_DATA !== 'undefined' && Array.isArray(EXAM_CENTERS_DATA)) {

    const cityData = {};

    EXAM_CENTERS_DATA.forEach(center => {

        if (!cityData[center.city]) {
            cityData[center.city] = [];
        }

        cityData[center.city].push(center.score);
    });

    labels = Object.keys(cityData);

    riskScores = labels.map(city => {

        const scores = cityData[city];

        const averageScore =
            scores.reduce((sum, score) => sum + score, 0) / scores.length;

        return 100 - averageScore;
    });
}

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: "Risk Index (%)",
                    data: riskScores,
                    backgroundColor: riskScores.map(score => {
                        if (score < 15) return "#22c55e"; // Low Risk
                        if (score < 30) return "#fbbf24"; // Medium Risk
                        return "#ef4444"; // High Risk
                    }),
                    borderRadius: 8,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: "#94A3B8",
                            font: { family: 'Poppins', size: 12 }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: "#94A3B8",
                            font: { family: 'Poppins' }
                        },
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    },
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            color: "#94A3B8",
                            font: { family: 'Poppins' }
                        },
                        grid: { color: "rgba(255, 255, 255, 0.05)" }
                    }
                }
            }
        });
    }
});
