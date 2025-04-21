from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class ViewCountRule(Rule):
    id = 'GVIEWS'
    description = 'Dashboards containing excessive number of views (>16).'
    group = 'Design Complexity'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for dash in tree.findall('.//dashboard'):
            views = dash.findall('.//view')
            if len(views) > 16:
                findings.append(Finding(self.id,
                    f"Dashboard '{dash.get('name')}' has {len(views)} views.",
                    'NEEDS_REVIEW'))
        return findings