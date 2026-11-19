// Récupère les statistiques et dessine les graphiques du dashboard
const COLORS = {
    sshtrap: "#3b82f6",
    loghunter: "#22c55e",
    miniwaf: "#f59e0b",
    watchtower: "#ef4444",
    test: "#94a3b8",
};

Chart.defaults.color = "#cbd5e1";
Chart.defaults.borderColor = "#334155";

async function loadCharts() {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();

    new Chart(document.getElementById("timelineChart"), {
        type: "bar",
        data: {
            labels: data.timeline.labels,
            datasets: [{ label: "Alertes", data: data.timeline.values, backgroundColor: "#3b82f6" }],
        },
        options: {
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
    });

    const sources = Object.keys(data.stats.by_source);
    new Chart(document.getElementById("sourceChart"), {
        type: "doughnut",
        data: {
            labels: sources,
            datasets: [{
                data: sources.map((s) => data.stats.by_source[s]),
                backgroundColor: sources.map((s) => COLORS[s] || "#64748b"),
                borderWidth: 0,
            }],
        },
        options: { plugins: { legend: { position: "bottom" } } },
    });
}

loadCharts();
