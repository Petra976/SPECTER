from datetime import datetime
import json
import html


def risk_score(results):
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    return min(sum(weights.get(r.get("severity", "info").lower(), 1) for r in results), 100)


def generate_html_report(results, path, target, company_logo=""):
    score = risk_score(results)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev_counts[r.get("severity", "info").lower()] += 1

    findings_json = json.dumps(results)

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>WRAITH Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
    background: radial-gradient(circle at top, #0f2027, #0d1117);
    color: #e6edf3;
    font-family: 'Consolas', monospace;
    margin: 0;
    padding: 30px;
}}
h1, h2 {{ color: #00e5ff; }}
.header {{ display:flex; justify-content:space-between; border-bottom:1px solid #30363d; }}
.score {{ font-size:42px; font-weight:bold; color:#ff3b3b; }}
.card {{
    background:#161b22;
    border-radius:10px;
    margin-bottom:12px;
    padding:14px;
    border-left:6px solid;
    box-shadow:0 0 10px #000;
}}
.critical {{ border-color:#ff1744; }}
.high {{ border-color:#ff9100; }}
.medium {{ border-color:#ffd600; }}
.low {{ border-color:#00e676; }}
.info {{ border-color:#40c4ff; }}
.details {{ display:none; margin-top:10px; }}
pre {{ background:#0d1117; padding:8px; border-radius:6px; }}
button {{
    background:#1f6feb; border:none; padding:6px 10px;
    color:white; border-radius:6px; cursor:pointer;
}}
</style>
</head>
<body>

<div class="header">
<div>
<h1>WRAITH Security Assessment</h1>
<p><b>Target:</b> {target}</p>
<p><b>Date:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
</div>
<div class="score">{score}/100</div>
</div>

<h2>Severity Overview</h2>
<canvas id="sevChart"></canvas>

<h2>Technical Findings</h2>
<div id="findings"></div>

<script>
const findings = {findings_json};

function toggle(id) {{
    let el = document.getElementById(id);
    el.style.display = el.style.display === "none" ? "block" : "none";
}}

findings.forEach((f,i)=>{{
    let card = document.createElement("div");
    card.className = "card " + f.severity.toLowerCase();

    card.innerHTML = `
        <div onclick="toggle('d${{i}}')" style="cursor:pointer;">
            <b>${{f.title}}</b> — ${{f.severity.toUpperCase()}}
        </div>
        <div id="d${{i}}" class="details">
            <p><b>Module:</b> ${{f.module}}</p>
            <p><b>Category:</b> ${{f.category}}</p>
            <p><b>Endpoint:</b> ${{f.endpoint}}</p>
            <p><b>Description:</b><br>${{f.description}}</p>
            <p><b>Business Impact:</b><br>${{f.business_impact}}</p>
            <p><b>Remediation:</b><br>${{f.remediation}}</p>
            ${{f.notes ? `<p><b>Pentester Notes:</b><br>${{f.notes}}</p>` : ''}}
            ${{f.evidence ? `<pre>${{JSON.stringify(f.evidence,null,2)}}</pre>` : ''}}
        </div>`;
    document.getElementById("findings").appendChild(card);
}});

new Chart(document.getElementById('sevChart'), {{
type:'bar',
data:{{
labels:{list(sev_counts.keys())},
datasets:[{{data:{list(sev_counts.values())}}}]
}}
}});
</script>

</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
