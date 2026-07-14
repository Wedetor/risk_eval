import os

def generate_html_chart(metrics_data, output_dir="reports", html_filename="risk_visual.html"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, html_filename)

    # Get risk vectors, default to 0 if skipped
    simple = metrics_data.get("Results", {}).get("Simple_Induction", {}).get("Risk_Vector_Rd", {"R_hs": 0, "R_hu": 0, "R_ho": 0})
    advanced = metrics_data.get("Results", {}).get("Advanced_Induction", {}).get("Risk_Vector_Rd", {"R_hs": 0, "R_hu": 0, "R_ho": 0})
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RiskEval - Rd Vector Report</title>
    <!-- Chart.js loaded via CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f6f9; }}
        .container {{ max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        h2 {{ text-align: center; color: #2c3e50; margin-bottom: 5px; }}
        p.subtitle {{ text-align: center; color: #7f8c8d; margin-top: 0; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Multidimensional Risk Audit (Vector R<sub>d</sub>)</h2>
        <p class="subtitle">Severity Comparison: Simple vs. Advanced Induction</p>
        <canvas id="riskChart" width="400" height="220"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('riskChart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: ['System Risk (R_hs)', 'User Risk (R_hu)', 'Third-Party Risk (R_ho)'],
                datasets: [
                    {{
                        label: 'Simple Induction (δ = 0.77)',
                        data: [{simple.get('R_hs', 0)}, {simple.get('R_hu', 0)}, {simple.get('R_ho', 0)}],
                        backgroundColor: 'rgba(54, 162, 235, 0.75)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }},
                    {{
                        label: 'Advanced Induction (δ = 0.44)',
                        data: [{advanced.get('R_hs', 0)}, {advanced.get('R_hu', 0)}, {advanced.get('R_ho', 0)}],
                        backgroundColor: 'rgba(255, 99, 132, 0.75)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1,
                        borderRadius: 4
                    }}
                ]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ 
                        beginAtZero: true, 
                        max: 10, 
                        title: {{ display: true, text: 'Risk Level (0.0 - 10.0)', font: {{ weight: 'bold' }} }} 
                    }}
                }},
                plugins: {{
                    legend: {{ position: 'top' }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
    
    # Corrected bug: open filepath instead of html_filename
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[i] HTML visualizer saved to: '{filepath}'")