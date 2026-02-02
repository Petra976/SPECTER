from datetime import datetime
import json
import html

def risk_score(results):
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    total_score = sum(weights.get(r.get("severity", "info").lower(), 1) for r in results)
    return min(total_score, 100)

def generate_html_report(results, path, target):
    # Calcular métricas
    score = risk_score(results)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for r in results:
        severity = r.get("severity", "info").lower()
        if severity in sev_counts:
            sev_counts[severity] += 1
        else:
            sev_counts["info"] += 1

    # Preparar dados para o JS
    findings_json = json.dumps(results)
    chart_data = list(sev_counts.values())
    
    # Cores para o gráfico e CSS
    colors = {
        "critical": "#ff2e63", # Red/Pink
        "high": "#ff6f61",     # Orange
        "medium": "#feb236",   # Yellow
        "low": "#00bcd4",      # Cyan
        "info": "#6c757d"      # Grey
    }

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPECTER Audit Report - {html.escape(target)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --border-color: #30363d;
            --accent: #58a6ff;
            
            --sev-critical: {colors['critical']};
            --sev-high: {colors['high']};
            --sev-medium: {colors['medium']};
            --sev-low: {colors['low']};
            --sev-info: {colors['info']};
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}

        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px; }}

        /* --- HEADER --- */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{ margin: 0; font-size: 28px; color: #fff; letter-spacing: -0.5px; }}
        .meta {{ color: var(--text-muted); font-size: 14px; margin-top: 5px; }}

        /* --- DASHBOARD GRID --- */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .stat-val {{ font-size: 32px; font-weight: 700; color: #fff; }}
        .stat-label {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }}
        
        .score-box {{ color: var(--sev-critical); }}
        
        /* --- CHART SECTION --- */
        .chart-container {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 40px;
            display: flex;
            justify-content: center;
            height: 300px;
            position: relative;
        }}

        /* --- FILTERS --- */
        .controls {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
        }}

        /* --- FINDINGS LIST --- */
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: transform 0.2s;
        }}
        .finding-card:hover {{ transform: translateY(-2px); border-color: var(--text-muted); }}

        .finding-header {{
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: linear-gradient(90deg, rgba(255,255,255,0.02), transparent);
        }}

        .finding-title {{ font-weight: 600; font-size: 16px; color: #fff; display: flex; align-items: center; gap: 10px; }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #1e1e2e;
        }}
        .badge.critical {{ background: var(--sev-critical); }}
        .badge.high {{ background: var(--sev-high); }}
        .badge.medium {{ background: var(--sev-medium); }}
        .badge.low {{ background: var(--sev-low); }}
        .badge.info {{ background: var(--sev-info); color: #fff; }}

        .chevron {{ transition: transform 0.3s; color: var(--text-muted); }}
        .finding-card.open .chevron {{ transform: rotate(180deg); }}

        .finding-body {{
            display: none;
            padding: 20px;
            border-top: 1px solid var(--border-color);
            background: #0f131a;
        }}
        .finding-card.open .finding-body {{ display: block; }}

        /* --- CONTENT STYLING --- */
        .section-title {{
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 5px;
            margin-top: 15px;
            font-weight: 700;
        }}
        .section-title:first-child {{ margin-top: 0; }}
        
        p {{ margin: 0 0 10px 0; font-size: 14px; color: var(--text-main); }}
        
        pre {{
            background: #050505;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid #30363d;
            font-family: 'Fira Code', monospace;
            font-size: 13px;
            color: #a5d6ff;
        }}

        /* Helper for JSON syntax highlighting colors (simulated) */
        .key {{ color: #7ee787; }}
        .string {{ color: #a5d6ff; }}
        .number {{ color: #79c0ff; }}

    </style>
</head>
<body>

<div class="container">
    <header>
        <div>
            <h1>WRAITH <span style="color:var(--accent); font-weight:300;">REPORT</span></h1>
            <div class="meta">
                Target: <b>{html.escape(target)}</b> &bull; 
                Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}
            </div>
        </div>
        <div style="text-align:right">
            <div style="font-size:12px; color:var(--text-muted);">RISK SCORE</div>
            <div class="stat-val score-box">{score}</div>
        </div>
    </header>

    <div class="dashboard">
        <div class="stat-card">
            <div>
                <div class="stat-val">{len(results)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div style="height:40px; width:40px; background:rgba(255,255,255,0.05); border-radius:50%;"></div>
        </div>
        <div class="stat-card">
            <div>
                <div class="stat-val" style="color:{colors['critical']}">{sev_counts['critical']}</div>
                <div class="stat-label">Critical Issues</div>
            </div>
        </div>
        <div class="stat-card">
            <div>
                <div class="stat-val" style="color:{colors['high']}">{sev_counts['high']}</div>
                <div class="stat-label">High Issues</div>
            </div>
        </div>
    </div>

    <div class="chart-container">
        <canvas id="sevChart"></canvas>
    </div>

    <h2 style="margin-bottom:20px; color:#fff;">Detailed Findings</h2>
    
    <div class="controls">
        <button class="filter-btn active" onclick="filterFindings('all')">All</button>
        <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
        <button class="filter-btn" onclick="filterFindings('high')">High</button>
        <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
        <button class="filter-btn" onclick="filterFindings('low')">Low</button>
    </div>

    <div id="findings-list"></div>
</div>

<script>
const findings = {findings_json};

// Inicializar Gráfico
const ctx = document.getElementById('sevChart').getContext('2d');
new Chart(ctx, {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{
            data: {chart_data},
            backgroundColor: [
                '{colors['critical']}',
                '{colors['high']}',
                '{colors['medium']}',
                '{colors['low']}',
                '{colors['info']}'
            ],
            borderWidth: 0
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ position: 'right', labels: {{ color: '#8b949e', font: {{ family: 'Inter' }} }} }}
        }}
    }}
}});

// Renderizar Findings
const container = document.getElementById('findings-list');

function render(filter = 'all') {{
    container.innerHTML = '';
    findings.forEach((f, i) => {{
        const sev = f.severity.toLowerCase();
        if (filter !== 'all' && sev !== filter) return;

        // Formatar Evidência
        let evidenceHtml = '';
        if (f.evidence) {{
            let content = f.evidence;
            if (typeof content === 'object') {{
                content = JSON.stringify(content, null, 2);
            }}
            evidenceHtml = `<div class="section-title">Technical Evidence</div><pre>${{content}}</pre>`;
        }}

        const card = document.createElement('div');
        card.className = 'finding-card ' + sev;
        card.innerHTML = `
            <div class="finding-header" onclick="toggleCard(this)">
                <div class="finding-title">
                    <span class="badge ${{sev}}">${{f.severity}}</span>
                    ${{f.title}}
                </div>
                <div class="chevron">▼</div>
            </div>
            <div class="finding-body">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:15px;">
                    <div><div class="section-title">Module</div><p>${{f.module}}</p></div>
                    <div><div class="section-title">Category</div><p>${{f.category}}</p></div>
                </div>
                
                <div class="section-title">Description</div>
                <p>${{f.description}}</p>
                
                <div class="section-title">Business Impact</div>
                <p>${{f.business_impact}}</p>
                
                <div class="section-title">Remediation</div>
                <p style="color:#7ee787">${{f.remediation}}</p>
                
                ${{f.endpoint ? `<div class="section-title">Endpoint</div><pre>${{f.endpoint}}</pre>` : ''}}
                ${{evidenceHtml}}
                ${{f.notes ? `<div class="section-title">Notes</div><p style="color:#feb236; font-style:italic;">${{f.notes}}</p>` : ''}}
            </div>
        `;
        container.appendChild(card);
    }});
}}

function toggleCard(header) {{
    header.parentElement.classList.toggle('open');
}}

function filterFindings(sev) {{
    render(sev);
    // Atualizar botões
    document.querySelectorAll('.filter-btn').forEach(b => {{
        b.classList.remove('active');
        if(b.textContent.toLowerCase() === sev) b.classList.add('active');
    }});
}}

// Render inicial
render();

</script>
</body>
</html>
"""
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"[+] Relatório HTML gerado em: {path}")

# Exemplo de uso (mock) se executado diretamente
if __name__ == "__main__":
    mock_data = [
        {"title": "Wix API Exposed", "severity": "high", "module": "wix_api", "category": "Info Disclosure", 
         "description": "Found public API functions.", "endpoint": "https://site.com/_functions", 
         "business_impact": "Data leak", "remediation": "Restrict access", "evidence": {"status": 200, "data": "users"}}
    ]
    generate_html_report(mock_data, "report.html", "https://target.com")