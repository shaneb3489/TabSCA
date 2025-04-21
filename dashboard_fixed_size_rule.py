from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class DashboardFixedSizeRule(Rule):
    id = 'GDASH_FIXED'
    description = 'Dashboards should have fixed sizing.'
    group = 'Design Consistency'
    severity = 'LOW'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for dash in tree.findall('.//dashboard'):
            if dash.get('automatic-size', 'true') == 'true':
                findings.append(Finding(self.id,
                    f"Dashboard '{dash.get('name')}' is not fixed size.",
                    'NEEDS_REVIEW'))
        return findings