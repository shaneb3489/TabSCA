#!/usr/bin/env python3

from __future__ import annotations
import argparse
import datetime
import html
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Sequence
import importlib.util
import inspect
from pathlib import Path
from rule_base import Rule, Finding

# Config file
# Create tableau_optimizer.json (or pass --config yourconfig.json) in the working directory:
# {
 #  "only": ["GBLEND","GUNUSED_DS"],
  # "skip": ["GCALC_LEN","GUNUSED_FIELDS"]
# }

def load_rules() ->list[Rule]:
    """Dynamically import all modules in rules/ and collect Rule subclasses."""
    rules: list[Rule] = []
    rules_dir = Path(__file__).parent / 'rules'
    for path in sorted(rules_dir.glob('*.py')):
        if path.name == '__init__.py':
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for obj in vars(mod).values():
            if inspect.isclass(obj) and issubclass(obj, Rule
                ) and obj is not Rule:
                rules.append(obj())
    return rules

def apply_rule_config(rules: list[Rule], config_path: Path) -> list[Rule]:
    """Read JSON config and filter the rules list accordingly."""
    if not config_path.exists():
        return rules

    cfg = json.loads(config_path.read_text())
    only = {r.upper() for r in cfg.get("only", [])}
    skip = {r.upper() for r in cfg.get("skip", [])}

    if only:
        # keep only those explicitly listed
        rules = [r for r in rules if r.id in only]
    if skip:
        # drop any in skip-list
        rules = [r for r in rules if r.id not in skip]

    return rules

# After loading dynamically:
RULES = load_rules()


REPORT_DIR = Path('reports')
REPORT_DIR.mkdir(exist_ok=True)


def write_html_report(wb_path: Path, findings: list[Finding]) ->Path:
    """Generate an HTML report with category filter and return the file path."""
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    generated = datetime.datetime.now().strftime('%Y‑%m‑%d\xa0%H:%M:%S\xa0%Z')
    out_file = REPORT_DIR / f'{wb_path.stem}_{ts}.html'
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.rule].append(f)
    severity_of = {r.id: r.severity for r in RULES}
    weight = {'INFO': 0, 'LOW': 1, 'MEDIUM': 3, 'HIGH': 5}
    penalty = sum(weight[severity_of[f.rule]] for f in findings)
    health_score = max(0, 100 - penalty)
    rule_by_id = {r.id: r for r in RULES}
    group_penalty: dict[str, int] = defaultdict(int)
    for f in findings:
        grp = rule_by_id[f.rule].group
        group_penalty[grp] += weight[severity_of[f.rule]]
    group_scores = {g: max(0, 100 - p) for g, p in group_penalty.items()}
    for g in {r.group for r in RULES}:
        group_scores.setdefault(g, 100)
    sev_totals = defaultdict(int)
    for f in findings:
        sev_totals[severity_of[f.rule]] += 1
    totals = {'total': len(findings), 'take_action': sum(1 for f in
        findings if f.category == 'TAKE_ACTION'), 'needs_review': sum(1 for
        f in findings if f.category == 'NEEDS_REVIEW')}
    rules_with_findings = set(grouped.keys())
    rules_passed = [(rule.id, rule.description, rule.group) for rule in
        RULES if rule.id not in rules_with_findings]
    rules_total = len(RULES)
    rules_ok = len(rules_passed)
    group_names = sorted({rule.group for rule in RULES})
    filter_html = f"""
<div class="filter-bar">
  <label for="categoryFilter"><strong>Category:</strong></label>
  <select id="categoryFilter" onchange="filterGroups()">
    <option value="All">All</option>
    {''.join(f'<option value="{html.escape(g)}">{html.escape(g)}</option>' for g in group_names)}
  </select>
&nbsp;&nbsp;
  <label for="severityFilter"><strong>Severity:</strong></label>
  <select id="severityFilter" onchange="filterGroups()">
    <option value="All">All</option>
    <option value="HIGH">HIGH</option>
    <option value="MEDIUM">MEDIUM</option>
    <option value="LOW">LOW</option>
    <option value="INFO">INFO</option>
  </select>
  <button id="themeToggle" title="Toggle light/dark mode"
          style="margin-left:auto; border:none; background:transparent; font-size:1.2em; cursor:pointer">
    🌙
  </button>
</div>
"""
    html_sections: list[str] = []
    passed_by_group: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for r_id, desc, grp in rules_passed:
        passed_by_group[grp].append((r_id, desc))
    for grp in group_names:
        passed_rules = passed_by_group.get(grp)
        if not passed_rules:
            continue
        html_sections.append(
            f"<details data-group='{html.escape(grp)}' data-status='Passed' data-sev='INFO'><summary><strong>✅\u202fRules\u202fPassed — {html.escape(grp)} ({len(passed_rules)})</strong></summary><ul>"
            )
        for r_id, desc in sorted(passed_rules):
            html_sections.append(
                f'<li>{html.escape(r_id)} — {html.escape(desc)}</li>')
        html_sections.append('</ul></details>')
    for rule in RULES:
        items = grouped.get(rule.id, [])
        if not items:
            continue
        html_sections.append(
            f"<details data-group='{html.escape(rule.group)}' data-sev='{html.escape(rule.severity)}'><summary><strong>{html.escape(rule.id)} — {len(items)} findings</strong></summary><p class='desc'>{html.escape(rule.description)}</p><ul>"
            )
        for f in items:
            style = 'take' if f.category == 'TAKE_ACTION' else 'review'
            html_sections.append(
                f"<li class='{style}'>❌ {html.escape(f.message)} ({f.category})</li>"
                )
        html_sections.append('</ul></details>')
    out_file.write_text(
        f"""<!doctype html>
<html><head>
  <meta charset='utf-8'>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(wb_path.name)} • Tableau Optimizer Report • {generated}</title>
  <style>
    body{{font-family:sans-serif;margin:2em}}
    h1{{font-size:1.8em;margin-bottom:0.5em}}
    .summary-block{{background:#eef;border:1px solid #ccd;padding:1em;margin-bottom:1.5em}}
    details{{margin-bottom:1em;border:1px solid #ccc;border-radius:4px;padding:0.75em;background:#f9f9f9}}
    summary{{font-size:1.1em;cursor:pointer}}
    ul{{padding-left:1.5em;margin-top:0.5em}}
    li{{margin:0.4em 0}}
    .take{{color:#c00;font-weight:bold}}
    .review{{color:#b8860b;font-weight:bold}}
    .desc{{font-size:0.95em;color:#333;margin:0.5em 0}}
    .score-bar{{position:relative;height:22px;background:#ddd;border-radius:4px;margin:0.4em 0 0.8em}}
    .score-fill{{background:#4caf50;height:100%;border-radius:4px}}
    .score-label{{position:absolute;top:0;left:50%;transform:translateX(-50%);font-weight:bold;font-size:0.9em;color:#000}}
    .sev.HIGH{{color:#c00;font-weight:bold}}
    .sev.MEDIUM{{color:#b8860b;font-weight:bold}}
    .sev.LOW{{color:#0066cc;font-weight:bold}}
    table.scorecard{{border-collapse:collapse;margin-top:0.8em}}
    .scorecard th, .scorecard td{{border:1px solid #bbb;padding:4px 8px}}
    .scorecard th{{background:#f0f0f8}}
    .filter-bar{{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.5em;
      position: sticky;
      top: 0;
      background: inherit;
      padding-top: 1em;
      padding-bottom: 0.5em;
      z-index: 10;
    }}
    /* OS‑dark only when NOT in light‑mode */
    @media (prefers-color-scheme: dark) {{
      :root:not(.light-mode) body {{
        background: #121212; color: #e0e0e0;
      }}
      :root:not(.light-mode) details {{
        background: #1e1e1e; border-color: #333;
      }}
      :root:not(.light-mode) summary {{ color: #eee; }}
      :root:not(.light-mode) .summary-block,
      :root:not(.light-mode) .filter-bar {{
        background: #1a1a1a; border-color: #333;
      }}
      :root:not(.light-mode) .score-bar {{ background: #333; }}
      :root:not(.light-mode) .score-fill {{ background: #76c7c0; }}
      :root:not(.light-mode) table.scorecard th,
      :root:not(.light-mode) table.scorecard td {{ border-color: #555; }}
    }}

    /* Manual dark‑mode override */
    .dark-mode body {{ background: #121212; color: #e0e0e0; }}
    .dark-mode details {{ background: #1e1e1e; border-color: #333; }}
    .dark-mode summary {{ color: #eee; }}
    .dark-mode .summary-block,
    .dark-mode .filter-bar {{ background: #1a1a1a; border-color: #333; }}
    .dark-mode .score-bar {{ background: #333; }}
    .dark-mode .score-fill {{ background: #76c7c0; }}
    .dark-mode table.scorecard th,
    .dark-mode table.scorecard td {{ border-color: #555; }}
    @media (max-width: 600px) {{
      body {{ font-size: 0.9em; }}
      h1 {{ font-size: 1.4em; }}
      .scorecard td, .scorecard th {{ padding: 2px 4px; }}
    }}
  </style>
    <script>
    function filterGroups () {{
      const catSel = document.getElementById('categoryFilter').value;
      const sevSel = document.getElementById('severityFilter').value;
      document.querySelectorAll('details[data-group]').forEach(d => {{
        const g   = d.getAttribute('data-group');
        const sev = d.getAttribute('data-sev');
        const showCat = (catSel === 'All' || g === catSel);
        const showSev = (sevSel === 'All' || sev === sevSel);
        d.style.display = (showCat && showSev) ? 'block' : 'none';
      }});
    }}

    // ── Theme toggle with light‑mode gating ──────────────────────
    document.addEventListener('DOMContentLoaded', function() {{
      const btn = document.getElementById('themeToggle');
      // decide initial mode: stored → else OS → else default light
      const stored = localStorage.getItem('theme');
      if (stored === 'dark') {{
        document.documentElement.classList.add('dark-mode');
      }} else if (stored === 'light') {{
        document.documentElement.classList.add('light-mode');
      }} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {{
        document.documentElement.classList.add('dark-mode');
      }} else {{
        document.documentElement.classList.add('light-mode');
      }}
      // set correct icon
      btn.textContent = document.documentElement.classList.contains('dark-mode')
                        ? '☀️' : '🌙';

      btn.addEventListener('click', function() {{
        const isDark = document.documentElement.classList.toggle('dark-mode');
        // ensure light‑mode is the opposite
        if (isDark) {{
          document.documentElement.classList.remove('light-mode');
          localStorage.setItem('theme', 'dark');
          btn.textContent = '☀️';
        }} else {{
          document.documentElement.classList.add('light-mode');
          localStorage.setItem('theme', 'light');
          btn.textContent = '🌙';
        }}
      }});
    }});
  </script>
</head><body>
  <h1>Static Code Analysis Report</h1>
    <p style="margin-top:-0.5em;font-size:0.95em;color:#555;">
        <strong>Workbook:</strong> {html.escape(wb_path.name)} &nbsp;|&nbsp;
        <strong>Generated:</strong> {generated}
    </p>
  <div class='summary-block'>
    <strong>Health&nbsp;Score:</strong>
    <div class="score-bar">
      <div class="score-fill" style="width:{health_score}%;"></div>
      <span class="score-label">{health_score}</span>
    </div>

    <table class="scorecard">
      <tr><th>Category</th><th>Score</th></tr>
      {''.join(f'<tr><td>{html.escape(g)}</td><td>{s}</td></tr>' for g, s in sorted(group_scores.items()))}
    </table>

    <p>
      <strong>Total Findings:</strong> {totals['total']}<br>
      <span class='sev HIGH'>HIGH:</span> {sev_totals.get('HIGH', 0)} &nbsp;
      <span class='sev MEDIUM'>MED:</span> {sev_totals.get('MEDIUM', 0)} &nbsp;
      <span class='sev LOW'>LOW:</span> {sev_totals.get('LOW', 0)}
    </p>
  </div>
  {filter_html}
  {''.join(html_sections)}
</body></html>"""
        )
    return out_file


def _load_workbook_xml(path: Path) ->str:
    import zipfile
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.endswith('.twb'):
                return z.read(name).decode('utf-8')
    raise FileNotFoundError('Workbook XML (.twb) not found inside .twbx')


def analyze_workbook(path: Path) ->list[Finding]:
    tree = ET.ElementTree(ET.fromstring(_load_workbook_xml(path)))
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.check(tree))
    return findings


def write_json_report(wb_path: Path, findings: list[Finding]) ->Path:
    """Dump a machine‑readable report."""
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = REPORT_DIR / f'{wb_path.stem}_{ts}.json'
    severity_of = {r.id: r.severity for r in RULES}
    weight = {'INFO': 0, 'LOW': 1, 'MEDIUM': 3, 'HIGH': 5}
    health_score = max(0, 100 - sum(weight[severity_of[f.rule]] for f in
        findings))
    payload = {'workbook': wb_path.name, 'generated': datetime.datetime.
        utcnow().isoformat(timespec='seconds') + 'Z', 'health_score':
        health_score, 'findings': [{'rule': f.rule, 'severity': severity_of
        [f.rule], 'category': f.category, 'message': f.message} for f in
        findings]}
    out_file.write_text(json.dumps(payload, indent=2))
    return out_file


def main(argv: (Sequence[str] | None)=None) ->None:
    p = argparse.ArgumentParser(description='Tableau Workbook Optimizer checks'
        )
    p.add_argument('workbooks', nargs='+')
    p.add_argument('--format', choices=['html', 'json', 'both'], default=
        'html', help='Report output format (default: html)')
    p.add_argument('--fail-if-high', action='store_true', help=
        'Exit non-zero if any HIGH-severity findings are present')
    p.add_argument('--min-score', type=int, default=None, help=
        'Exit non-zero if health score falls below this threshold')
    p.add_argument('--fail-on', default='', help=
        'Comma‑separated rule IDs that trigger non‑zero exit')
    p.add_argument('--config', type=Path, default=None, help=
        'Path to JSON config file with "only" and/or "skip" rule lists'
    )

    args = p.parse_args(argv)
    fail_set = {r.upper() for r in args.fail_on.split(',') if r}
    fmt = args.format
    fail_if_high = args.fail_if_high
    min_score = args.min_score
    config_path  = args.config or Path("tableau_optimizer.json")

    # then apply it to the already‐loaded RULES
    global RULES
    RULES = apply_rule_config(RULES, config_path)

    exit_code = 0

    for wb in args.workbooks:
        path = Path(wb)
        print(f'▶ {path.name}')
        try:
            issues = analyze_workbook(path)
            weight = {'INFO': 0, 'LOW': 1, 'MEDIUM': 3, 'HIGH': 5}
            severity_of = {r.id: r.severity for r in RULES}
            penalty = sum(weight[severity_of[f.rule]] for f in issues)
            health_score = max(0, 100 - penalty)
            print(f'  🎯  Health Score: {health_score}')
            if fail_if_high and any(severity_of[f.rule] == 'HIGH' for f in
                issues):
                print('⚠️  Aborting: HIGH-severity findings detected')
                exit_code = 1
            if min_score is not None and health_score < min_score:
                print(
                    f'⚠️  Aborting: health score {health_score} < threshold {min_score}'
                    )
                exit_code = 1
        except Exception as e:
            print(f'  ⚠️  {e}')
            exit_code = 1
            continue
        if fmt in ('html', 'both'):
            html_file = write_html_report(path, issues)
            print(f'  📄  HTML report written to {html_file}')
        if fmt in ('json', 'both'):
            json_file = write_json_report(path, issues)
            print(f'  📦  JSON report written to {json_file}')
        if any(f.rule in fail_set for f in issues):
            exit_code = 1
    raise SystemExit(exit_code)


if __name__ == '__main__':
    main()
