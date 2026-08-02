import os

def generate_html_chart(metrics_data, output_dir="reports", html_filename="risk_visual.html"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, html_filename)

    # Extract unified metrics
    unified = metrics_data.get("Results", {}).get("Unified_Evaluation", {})
    rd = unified.get("Primary_Metric_Rd", {"R_hs_System": 0, "R_hu_User": 0, "R_ho_ThirdParty": 0})
    rd_star = unified.get("Secondary_Metric_Rd_Star", {"R_hs_star_System": 0, "R_hu_star_User": 0, "R_ho_star_ThirdParty": 0})

    # Values
    hs = rd.get('R_hs_System', 0)
    hu = rd.get('R_hu_User', 0)
    ho = rd.get('R_ho_ThirdParty', 0)

    hs_s = rd_star.get('R_hs_star_System', 0)
    hu_s = rd_star.get('R_hu_star_User', 0)
    ho_s = rd_star.get('R_ho_star_ThirdParty', 0)

    # CVSS Color Mapper
    def get_cvss_style(val):
        if val <= 3.9:
            return "'rgba(34, 197, 94, 0.75)'", "'rgba(34, 197, 94, 1)'", "#16a34a"  # Low (Green)
        elif val <= 6.9:
            return "'rgba(234, 179, 8, 0.75)'", "'rgba(234, 179, 8, 1)'", "#ca8a04"   # Medium (Yellow)
        elif val <= 8.9:
            return "'rgba(239, 68, 68, 0.75)'", "'rgba(239, 68, 68, 1)'", "#dc2626"  # High (Red)
        else:
            return "'rgba(168, 85, 247, 0.75)'", "'rgba(168, 85, 247, 1)'", "#9333ea" # Critical (Purple)

    # Resolve colors for primary vector
    c_hs_bg, c_hs_bd, c_hs_txt = get_cvss_style(hs)
    c_hu_bg, c_hu_bd, c_hu_txt = get_cvss_style(hu)
    c_ho_bg, c_ho_bd, c_ho_txt = get_cvss_style(ho)

    # Resolve colors for secondary vector
    s_hs_bg, s_hs_bd, s_hs_txt = get_cvss_style(hs_s)
    s_hu_bg, s_hu_bd, s_hu_txt = get_cvss_style(hu_s)
    s_ho_bg, s_ho_bd, s_ho_txt = get_cvss_style(ho_s)

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
        .tag-unified {{ color: #2c3e50; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- SECTION 1: PRIMARY METRIC (Rd) -->
        <h2>Risk Audit (Vector R<sub>d</sub>)</h2>
        <p class="subtitle">Maximum Damage</p>
        <canvas id="riskChartRd" width="400" height="150"></canvas>
        <table>
            <thead>
                <tr><th>System Risk (R_hs)</th><th>User Risk (R_hu)</th><th>Third-Party Risk (R_ho)</th></tr>
            </thead>
            <tbody>
                <tr>
                    <td style="color: {c_hs_txt}; font-weight: bold;">{hs}</td>
                    <td style="color: {c_hu_txt}; font-weight: bold;">{hu}</td>
                    <td style="color: {c_ho_txt}; font-weight: bold;">{ho}</td>
                </tr>
            </tbody>
        </table>

        <hr>

        <!-- SECTION 2: SECONDARY METRIC (Rd*) -->
        <h2>Normalized Severity Audit (Vector R<sup>*</sup><sub>d</sub>)</h2>
        <p class="subtitle">Weighted Average Density</p>
        <canvas id="riskChartRdStar" width="400" height="150"></canvas>
        <table>
            <thead>
                <tr><th>System Risk (R_hs*)</th><th>User Risk (R_hu*)</th><th>Third-Party Risk (R_ho*)</th></tr>
            </thead>
            <tbody>
                <tr>
                    <td style="color: {s_hs_txt}; font-weight: bold;">{hs_s}</td>
                    <td style="color: {s_hu_txt}; font-weight: bold;">{hu_s}</td>
                    <td style="color: {s_ho_txt}; font-weight: bold;">{ho_s}</td>
                </tr>
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
                    data: [{hs}, {hu}, {ho}],
                    backgroundColor: [{c_hs_bg}, {c_hu_bg}, {c_ho_bg}],
                    borderColor: [{c_hs_bd}, {c_hu_bd}, {c_ho_bd}],
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
                    data: [{hs_s}, {hu_s}, {ho_s}],
                    backgroundColor: [{s_hs_bg}, {s_hu_bg}, {s_ho_bg}],
                    borderColor: [{s_hs_bd}, {s_hu_bd}, {s_ho_bd}],
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