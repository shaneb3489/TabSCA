from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class BlendRule(Rule):
    id = 'GBLEND'
    description = 'Worksheets that blend multiple data sources.'
    group = 'Performance'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for ws in tree.findall('.//worksheet'):
            blends = ws.findall('.//datasource-dependencies')
            if len(blends) > 1:
                name = ws.get('name', '(unnamed)')
                findings.append(Finding(self.id,
                    f"Worksheet '{name}' references {len(blends)} data sources."
                    , 'NEEDS_REVIEW'))
        return findings