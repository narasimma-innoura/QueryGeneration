import os

files = [
    'static/auditor_frontend.html',
    'static/auditor_frontend_v3.html',
    'static/auditor_frontend_v4.html'
]

chart_func = """
let currentChart = null;
function displayChart(counts) {
    const container = document.getElementById("resultsContainer");
    
    if (Object.keys(counts).length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No detections found to chart.</p></div>`;
        return;
    }

    container.innerHTML = `<canvas id="alertChart" width="400" height="200"></canvas>`;
    const ctx = document.getElementById("alertChart").getContext("2d");
    
    if (currentChart) {
        currentChart.destroy();
    }
    
    const labels = Object.keys(counts);
    const data = Object.values(counts);
    
    currentChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alert Breakdown',
                data: data,
                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}
"""

for file in files:
    with open(file, 'r') as f:
        content = f.read()

    # 1. Add Chart.js script
    content = content.replace('</head>', '    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n</head>')

    # 2. Update LLM Rule
    old_rule = '3. If asking for trends or graphs, use GROUP BY. To group by date, use: TO_TIMESTAMP(start_ms / 1000.0)::DATE'
    new_rule = '3. If asking for a chart, graph, or breakdown, DO NOT use GROUP BY or COUNT. ALWAYS use SELECT detections FROM video_segments and apply the requested filters (e.g. date). The frontend will handle charting.'
    content = content.replace(old_rule, new_rule)

    # 3. Add isChartRequest boolean
    content = content.replace('const textPrompt = document.getElementById("auditInput").value.trim();', 'const textPrompt = document.getElementById("auditInput").value.trim();\n    const isChartRequest = /chart|graph|plot|breakdown/i.test(textPrompt);')

    # 4. Intercept JSON response for chart
    old_fetch_logic = """        if (typeof data === "number" || typeof data === "string") {"""
    new_fetch_logic = """        if (isChartRequest && Array.isArray(data)) {
            const counts = {};
            data.forEach(segment => {
                if (segment.detections && segment.detections.frames) {
                    segment.detections.frames.forEach(frame => {
                        if (frame.boxes) {
                            frame.boxes.forEach(box => {
                                const label = box.label;
                                counts[label] = (counts[label] || 0) + 1;
                            });
                        }
                    });
                }
            });
            displayChart(counts);
            document.getElementById("queryStatus").textContent = "success";
            document.getElementById("resultCount").textContent = Object.keys(counts).length.toString();
            document.getElementById("queryTime").textContent = (performance.now() - startTime).toFixed(2);
            log(`✓ Chart query completed | Rendering Chart`);
            return;
        }

        if (typeof data === "number" || typeof data === "string") {"""
    content = content.replace(old_fetch_logic, new_fetch_logic)

    # 5. Inject displayChart function
    content = content.replace('function displayResults(results) {', chart_func + '\nfunction displayResults(results) {')

    with open(file, 'w') as f:
        f.write(content)

print("Done charting implementation!")
