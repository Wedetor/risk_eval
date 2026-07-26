import os

def generate_html_chart(metrics_data, output_dir="reports", html_filename="risk_visual.html"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, html_filename)

    # Extract primary Rd vectors (default to 0 if skipped)
    simple_rd = metrics_data.get("Results", {}).get("Simple_Induction", {}).get("Risk_Vector_Rd", {"R_hs_System": 0, "R_hu_User": 0, "R_ho_ThirdParty": 0})
    advanced_rd = metrics_data.get("Results", {}).get("Advanced_Induction", {}).get("Risk_Vector_Rd", {"R_hs_System": 0, "R_hu_User": 0, "R_ho_ThirdParty": 0})
    
    # Extract secondary Rd* vectors (default to 0 if skipped)
    simple_star = metrics_data.get("Results", {}).get("Simple_Induction", {}).get("Secondary_Metric_Rd_Star", {"R_hs_star_System": 0, "R_hu_star_User": 0, "R_ho_star_ThirdParty": 0})
    advanced_star = metrics_data.get("Results", {}).get("Advanced_Induction", {}).get("Secondary_Metric_Rd_Star", {"R_hs_star_System": 0, "R_hu_star_User": 0, "R_ho_star_ThirdParty": 0})

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RiskEval - Multidimensional Risk Report</title>
    <!-- Chart.js loaded via CDN -->
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
        .tag-simple {{ color: #0284c7; font-weight: bold; }}
        .tag-adv {{ color: #e11d48; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- SECTION 1: PRIMARY METRIC (Rd) -->
        <h2>Multidimensional Risk Audit (Vector R<sub>d</sub>)</h2>
        <p class="subtitle">Maximum Potential Damage — Simple vs. Advanced Induction</p>
        <canvas id="riskChartRd" width="400" height="200"></canvas>
        <table>
            <thead>
                <tr><th>Evaluation Mode</th><th>System Risk (R_hs)</th><th>User Risk (R_hu)</th><th>Third-Party Risk (R_ho)</th></tr>
            </thead>
            <tbody>
                <tr><td class="tag-simple">Simple Induction (δ = 0.77)</td><td>{simple_rd.get('R_hs_System', 0)}</td><td>{simple_rd.get('R_hu_User', 0)}</td><td>{simple_rd.get('R_ho_ThirdParty', 0)}</td></tr>
                <tr><td class="tag-adv">Advanced Induction (δ = 0.44)</td><td>{advanced_rd.get('R_hs_System', 0)}</td><td>{advanced_rd.get('R_hu_User', 0)}</td><td>{advanced_rd.get('R_ho_ThirdParty', 0)}</td></tr>
            </tbody>
        </table>

        <hr>

        <!-- SECTION 2: SECONDARY METRIC (Rd*) -->
        <h2>Normalized Severity Audit (Vector R<sup>*</sup><sub>d</sub>)</h2>
        <p class="subtitle">Weighted Average Density — Simple vs. Advanced Induction</p>
        <canvas id="riskChartRdStar" width="400" height="200"></canvas>
        <table>
            <thead>
                <tr><th>Evaluation Mode</th><th>System Risk (R_hs*)</th><th>User Risk (R_hu*)</th><th>Third-Party Risk (R_ho*)</th></tr>
            </thead>
            <tbody>
                <tr><td class="tag-simple">Simple Induction (δ = 0.77)</td><td>{simple_star.get('R_hs_star_System', 0)}</td><td>{simple_star.get('R_hu_star_User', 0)}</td><td>{simple_star.get('R_ho_star_ThirdParty', 0)}</td></tr>
                <tr><td class="tag-adv">Advanced Induction (δ = 0.44)</td><td>{advanced_star.get('R_hs_star_System', 0)}</td><td>{advanced_star.get('R_hu_star_User', 0)}</td><td>{advanced_star.get('R_ho_star_ThirdParty', 0)}</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        const commonOptions = {{
            responsive: true,
            scales: {{
                y: {{ 
                    beginAtZero: true, 
                    max: 10, 
                    title: {{ display: true, text: 'Risk Level (0.0 - 10.0)', font: {{ weight: 'bold' }} }} 
                }}
            }},
            plugins: {{ legend: {{ position: 'top' }} }}
        }};

        // Render Chart 1: Primary Rd
        const ctxRd = document.getElementById('riskChartRd').getContext('2d');
        new Chart(ctxRd, {{
            type: 'bar',
            data: {{
                labels: ['System Risk (R_hs)', 'User Risk (R_hu)', 'Third-Party Risk (R_ho)'],
                datasets: [
                    {{
                        label: 'Simple Induction (δ = 0.77)',
                        data: [{simple_rd.get('R_hs_System', 0)}, {simple_rd.get('R_hu_User', 0)}, {simple_rd.get('R_ho_ThirdParty', 0)}],
                        backgroundColor: 'rgba(54, 162, 235, 0.75)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }},
                    {{
                        label: 'Advanced Induction (δ = 0.44)',
                        data: [{advanced_rd.get('R_hs_System', 0)}, {advanced_rd.get('R_hu_User', 0)}, {advanced_rd.get('R_ho_ThirdParty', 0)}],
                        backgroundColor: 'rgba(255, 99, 132, 0.75)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }}
                ]
            }},
            options: commonOptions
        }});

        // Render Chart 2: Secondary Rd*
        const ctxRdStar = document.getElementById('riskChartRdStar').getContext('2d');
        new Chart(ctxRdStar, {{
            type: 'bar',
            data: {{
                labels: ['System Risk (R_hs*)', 'User Risk (R_hu*)', 'Third-Party Risk (R_ho*)'],
                datasets: [
                    {{
                        label: 'Simple Induction (δ = 0.77)',
                        data: [{simple_star.get('R_hs_star_System', 0)}, {simple_star.get('R_hu_star_User', 0)}, {simple_star.get('R_ho_star_ThirdParty', 0)}],
                        backgroundColor: 'rgba(54, 162, 235, 0.75)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }},
                    {{
                        label: 'Advanced Induction (δ = 0.44)',
                        data: [{advanced_star.get('R_hs_star_System', 0)}, {advanced_star.get('R_hu_star_User', 0)}, {advanced_star.get('R_ho_star_ThirdParty', 0)}],
                        backgroundColor: 'rgba(255, 99, 132, 0.75)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }}
                ]
            }},
            options: commonOptions
        }});
    </script>
</body>
</html>"""

    # Save generated HTML report
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[i] HTML visualizer saved to: '{filepath}'")