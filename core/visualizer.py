import os
import json

def generate_html_chart(metrics_data, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    html_path = os.path.join(output_dir, "risk_visual.html")

    # Extract Simple Induction vectors
    simple_rd = [0.0, 0.0, 0.0]
    simple_rd_star = [0.0, 0.0, 0.0]
    if "Simple_Induction" in metrics_data["Results"]:
        res_s = metrics_data["Results"]["Simple_Induction"]
        simple_rd = [res_s["Risk_Vector_Rd"]["R_hs_System"], res_s["Risk_Vector_Rd"]["R_hu_User"], res_s["Risk_Vector_Rd"]["R_ho_ThirdParty"]]
        simple_rd_star = [res_s["Secondary_Metric_Rd_Star"]["R_hs_star_System"], res_s["Secondary_Metric_Rd_Star"]["R_hu_star_User"], res_s["Secondary_Metric_Rd_Star"]["R_ho_star_ThirdParty"]]

    # Extract Advanced Induction vectors
    adv_rd = [0.0, 0.0, 0.0]
    adv_rd_star = [0.0, 0.0, 0.0]
    if "Advanced_Induction" in metrics_data["Results"]:
        res_a = metrics_data["Results"]["Advanced_Induction"]
        adv_rd = [res_a["Risk_Vector_Rd"]["R_hs_System"], res_a["Risk_Vector_Rd"]["R_hu_User"], res_a["Risk_Vector_Rd"]["R_ho_ThirdParty"]]
        adv_rd_star = [res_a["Secondary_Metric_Rd_Star"]["R_hs_star_System"], res_a["Secondary_Metric_Rd_Star"]["R_hu_star_User"], res_a["Secondary_Metric_Rd_Star"]["R_ho_star_ThirdParty"]]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RiskEval - Dual Operational Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ text-align: center; color: #38bdf8; margin-bottom: 5px; }}
        p.subtitle {{ text-align: center; color: #94a3b8; margin-top: 0; margin-bottom: 30px; font-size: 1.1em; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 25px; margin-bottom: 35px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.5); border: 1px solid #334155; }}
        .card h2 {{ color: #e2e8f0; margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 10px; font-size: 1.4em; }}
        .card p.desc {{ color: #cbd5e1; font-size: 0.95em; line-height: 1.5; margin-bottom: 20px; }}
        .chart-container {{ position: relative; height: 380px; width: 100%; display: flex; justify-content: center; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; text-align: center; background: #0f172a; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px; border: 1px solid #334155; }}
        th {{ background: #334155; color: #38bdf8; font-weight: 600; }}
        td {{ color: #e2e8f0; }}
        .tag-simple {{ color: #fbbf24; font-weight: bold; }}
        .tag-adv {{ color: #f87171; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>RiskEval - Operational Risk Audit</h1>
        <p class="subtitle">Comparative analysis between Maximum potential damage (Rd) and Normalized weighted average (Rd*)</p>

        <!-- Card 1: Primary Metric Rd -->
        <div class="card">
            <h2>1. Primary metric (Rd) — Maximum potential damage focus</h2>
            <p class="desc">
                This evaluation projects risk under its most critical scenario. It uses the mathematical maximum function to severely penalize the system if a vulnerability is detected.
            </p>
            <div class="chart-container">
                <canvas id="chartRd"></canvas>
            </div>
            <table>
                <thead>
                    <tr><th>Evaluation mode</th><th>System risk (R_hs)</th><th>User risk (R_hu)</th><th>Third-Party risk (R_ho)</th></tr>
                </thead>
                <tbody>
                    <tr><td class="tag-simple">Simple induction (Static)</td><td>{simple_rd[0]}</td><td>{simple_rd[1]}</td><td>{simple_rd[2]}</td></tr>
                    <tr><td class="tag-adv">Advanced induction (Red Teaming)</td><td>{adv_rd[0]}</td><td>{adv_rd[1]}</td><td>{adv_rd[2]}</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Card 2: Secondary Metric Rd* -->
        <div class="card">
            <h2>2. Secondary metric (Rd*) — Normalized weighted averages</h2>
            <p class="desc">
                This evaluation normalizes transgressions by dividing them by the total available tests (|T|) and uses arithmetic averages between sub-risks.
            <div class="chart-container">
                <canvas id="chartRdStar"></canvas>
            </div>
            <table>
                <thead>
                    <tr><th>Evaluation mode</th><th>System risk (R_hs*)</th><th>User risk (R_hu*)</th><th>Third-Party risk (R_ho*)</th></tr>
                </thead>
                <tbody>
                    <tr><td class="tag-simple">Simple Induction (Static)</td><td>{simple_rd_star[0]}</td><td>{simple_rd_star[1]}</td><td>{simple_rd_star[2]}</td></tr>
                    <tr><td class="tag-adv">Advanced Induction (Red Teaming)</td><td>{adv_rd_star[0]}</td><td>{adv_rd_star[1]}</td><td>{adv_rd_star[2]}</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{
                r: {{
                    angleLines: {{ color: '#334155' }},
                    grid: {{ color: '#334155' }},
                    pointLabels: {{ color: '#f8fafc', font: {{ size: 14, weight: 'bold' }} }},
                    suggestedMin: 0,
                    suggestedMax: 10,
                    ticks: {{ color: '#94a3b8', backdropColor: 'transparent', stepSize: 2 }}
                }}
            }},
            plugins: {{ legend: {{ labels: {{ color: '#e2e8f0', font: {{ size: 13 }} }} }} }}
        }};

        // Render Chart 1: Primary Rd
        new Chart(document.getElementById('chartRd'), {{
            type: 'radar',
            data: {{
                labels: ['R_hs (System)', 'R_hu (User)', 'R_ho (Third-Party)'],
                datasets: [
                    {{ label: 'Simple induction (Rd)', data: {simple_rd}, borderColor: '#fbbf24', backgroundColor: 'rgba(251, 191, 36, 0.2)', borderWidth: 2, pointBackgroundColor: '#fbbf24' }},
                    {{ label: 'Advanced induction (Rd)', data: {adv_rd}, borderColor: '#f87171', backgroundColor: 'rgba(248, 113, 113, 0.2)', borderWidth: 2, pointBackgroundColor: '#f87171' }}
                ]
            }},
            options: chartOptions
        }});

        // Render Chart 2: Secondary Rd*
        new Chart(document.getElementById('chartRdStar'), {{
            type: 'radar',
            data: {{
                labels: ['R_hs* (System Norm.)', 'R_hu* (User Norm.)', 'R_ho* (Third-Party Norm.)'],
                datasets: [
                    {{ label: 'Simple induction (Rd*)', data: {simple_rd_star}, borderColor: '#38bdf8', backgroundColor: 'rgba(56, 189, 248, 0.2)', borderWidth: 2, pointBackgroundColor: '#38bdf8' }},
                    {{ label: 'Advanced induction (Rd*)', data: {adv_rd_star}, borderColor: '#a78bfa', backgroundColor: 'rgba(167, 139, 250, 0.2)', borderWidth: 2, pointBackgroundColor: '#a78bfa' }}
                ]
            }},
            options: chartOptions
        }});
    </script>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[i] Dual HTML visualizer saved to: '{html_path}'")