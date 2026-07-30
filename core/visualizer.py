import os

def generate_html_chart(metrics_data, output_dir="reports", html_filename="risk_visual.html"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, html_filename)

    # Extract unified metrics
    unified = metrics_data.get("Results", {}).get("Unified_Evaluation", {})
    rd = unified.get("Primary_Metric_Rd", {"R_hs_System": 0, "R_hu_User": 0, "R_ho_ThirdParty": 0})
    rd_star = unified.get("Secondary_Metric_Rd_Star", {"R_hs_star_System": 0, "R_hu_star_User": 0, "R_ho_star_ThirdParty": 0})

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RiskEval - Unified Risk Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f6f9; color: #2c3e50; }}
        .container {{ max-width: 850px; margin: auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        h2 {{ text-align: center; color: #2c3e50; margin-bottom: 5px; }}
        p.subtitle {{ text-align: center; color: #7f8c8d; margin-top: 0; margin-bottom: 25px; font-size: 0.95em; }}
        hr {{ border: 0; height: 1px; background: #e2e8f0; margin: 45px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; text-align: center; }}
        th, td {{ padding: 10px; border: 1px solid #e2e8f0; }}
        th {{ background-color: #f8fafc; color: #475569; font-weight: 600; }}
        .tag-unified {{ color: #7c3aed; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- SECTION 1: PRIMARY METRIC (Rd) -->
        <h2>Unified Risk Audit (Vector R<sub>d</sub>)</h2>
        <p class="subtitle">Maximum Damage Model (10-Pass Average)</p>
        <canvas id="riskChartRd" width="400" height="150"></canvas>
        <table>
            <thead>
                <tr><th>Evaluation Mode</th><th>System Risk (R_hs)</th><th>User Risk (R_hu)</th><th>Third-Party Risk (R_ho)</th></tr>
            </thead>
            <tbody>
                <tr><td class="tag-unified">Unified Model</td><td>{rd.get('R_hs_System', 0)}</td><td>{rd.get('R_hu_User', 0)}</td><td>{rd.get('R_ho_ThirdParty', 0)}</td></tr>
            </tbody>
        </table>

        <hr>

        <!-- SECTION 2: SECONDARY METRIC (Rd*) -->
        <h2>Normalized Severity Audit (Vector R<sup>*</sup><sub>d</sub>)</h2>
        <p class="subtitle">Weighted Average Density Focus — Normalized by total |T|</p>
        <canvas id="riskChartRdStar" width="400" height="150"></canvas>
        <table>
            <thead>
                <tr><th>Evaluation Mode</th><th>System Risk (R_hs*)</th><th>User Risk (R_hu*)</th><th>Third-Party Risk (R_ho*)</th></tr>
            </thead>
            <tbody>
                <tr><td class="tag-unified">Unified Model</td><td>{rd_star.get('R_hs_star_System', 0)}</td><td>{rd_star.get('R_hu_star_User', 0)}</td><td>{rd_star.get('R_ho_star_ThirdParty', 0)}</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        const commonOptions = {{
            responsive: true,
            scales: {{ y: {{ beginAtZero: true, max: 10, title: {{ display: true, text: 'Risk Level (0.0 - 10.0)', font: {{ weight: 'bold' }} }} }} }},
            plugins: {{ legend: {{ display: false }} }}
        }};

        new Chart(document.getElementById('riskChartRd').getContext('2d'), {{
            type: 'bar',
            data: {{
                labels: ['System Risk (R_hs)', 'User Risk (R_hu)', 'Third-Party Risk (R_ho)'],
                datasets: [{{
                    data: [{rd.get('R_hs_System', 0)}, {rd.get('R_hu_User', 0)}, {rd.get('R_ho_ThirdParty', 0)}],
                    backgroundColor: 'rgba(124, 58, 237, 0.75)',
                    borderColor: 'rgba(124, 58, 237, 1)',
                    borderWidth: 1, borderRadius: 4
                }}]
            }},
            options: commonOptions
        }});

        new Chart(document.getElementById('riskChartRdStar').getContext('2d'), {{
            type: 'bar',
            data: {{
                labels: ['System Risk (R_hs*)', 'User Risk (R_hu*)', 'Third-Party Risk (R_ho*)'],
                datasets: [{{
                    data: [{rd_star.get('R_hs_star_System', 0)}, {rd_star.get('R_hu_star_User', 0)}, {rd_star.get('R_ho_star_ThirdParty', 0)}],
                    backgroundColor: 'rgba(16, 185, 129, 0.75)',
                    borderColor: 'rgba(16, 185, 129, 1)',
                    borderWidth: 1, borderRadius: 4
                }}]
            }},
            options: commonOptions
        }});
    </script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[i] HTML visualizer saved to: '{filepath}'")