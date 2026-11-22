import json
import os

# CVSS severity bands (thesis 5.4.2): low [0, 4), medium [4, 7), high [7, 9), critical [9, 10].
_BANDS = [(4.0, "34, 197, 94", "#16a34a"),      # low (green)
          (7.0, "234, 179, 8", "#ca8a04"),      # medium (yellow)
          (9.0, "239, 68, 68", "#dc2626"),      # high (red)
          (float("inf"), "168, 85, 247", "#9333ea")]  # critical (purple)

_VECTORS = [  # (canvas id, title, subtitle, result key, [(label, value key), ...])
    ("riskChartRd", "Risk Audit (Vector R<sub>d</sub>)", "Maximum Damage", "Primary_Metric_Rd",
     [("System Risk (R_hs)", "R_hs_System"), ("User Risk (R_hu)", "R_hu_User"),
      ("Third-Party Risk (R_ho)", "R_ho_ThirdParty")]),
    ("riskChartRdStar", "Normalized Severity Audit (Vector R<sup>*</sup><sub>d</sub>)", "Weighted Average Density",
     "Secondary_Metric_Rd_Star",
     [("System Risk (R_hs*)", "R_hs_star_System"), ("User Risk (R_hu*)", "R_hu_star_User"),
      ("Third-Party Risk (R_ho*)", "R_ho_star_ThirdParty")]),
]


def _band(value):
    return next((rgb, text) for limit, rgb, text in _BANDS if value < limit)


def generate_html_chart(metrics_data, output_dir="reports", html_filename="risk_visual.html"):
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, html_filename)
    unified = metrics_data.get("Results", {}).get("Unified_Evaluation", {})

    sections, charts = [], []
    for canvas, title, subtitle, key, columns in _VECTORS:
        values = [unified.get(key, {}).get(value_key, 0) for _, value_key in columns]
        bands = [_band(v) for v in values]
        header = "".join(f"<th>{label}</th>" for label, _ in columns)
        cells = "".join(f'<td style="color: {text}; font-weight: bold;">{v}</td>' for v, (_, text) in zip(values, bands))
        sections.append(f"""
        <h2>{title}</h2>
        <p class="subtitle">{subtitle}</p>
        <canvas id="{canvas}" width="400" height="150"></canvas>
        <table><thead><tr>{header}</tr></thead><tbody><tr>{cells}</tr></tbody></table>""")
        charts.append({"id": canvas, "labels": [label for label, _ in columns], "data": values,
                       "bg": [f"rgba({rgb}, 0.75)" for rgb, _ in bands],
                       "border": [f"rgba({rgb}, 1)" for rgb, _ in bands]})

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RiskEval - Unified Risk Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f6f9; color: #2c3e50; }}
        .container {{ max-width: 850px; margin: auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        h2 {{ text-align: center; color: #2c3e50; margin-bottom: 5px; }}
        p.subtitle {{ text-align: center; color: #7f8c8d; margin-top: 0; margin-bottom: 25px; font-size: 0.95em; }}
        hr {{ border: 0; height: 1px; background: #e2e8f0; margin: 45px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; text-align: center; }}
        th, td {{ padding: 10px; border: 1px solid #e2e8f0; }}
        th {{ background-color: #f8fafc; color: #475569; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">{"<hr>".join(sections)}
    </div>
    <script>
        const options = {{
            responsive: true,
            scales: {{ y: {{ beginAtZero: true, max: 10, title: {{ display: true, text: 'Risk Level (0.0 - 10.0)', font: {{ weight: 'bold' }} }} }} }},
            plugins: {{ legend: {{ display: false }} }}
        }};
        for (const c of {json.dumps(charts)}) {{
            new Chart(document.getElementById(c.id), {{
                type: 'bar',
                data: {{ labels: c.labels, datasets: [{{ data: c.data, backgroundColor: c.bg, borderColor: c.border,
                                                        borderWidth: 1, borderRadius: 4 }}] }},
                options: options
            }});
        }}
    </script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[i] HTML visualizer saved to: '{filepath}'")
