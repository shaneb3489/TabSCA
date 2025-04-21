from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class LiveConnectionRule(Rule):
    id = 'GLIVE_CONN'
    description = 'Detect live connections (prefer extracts).'
    group = 'Connectivity'
    severity = 'HIGH'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        live = tree.findall('.//connection[@class="sqlproxy"]')
        return [Finding(self.id, 'Workbook uses live connections.',
            'NEEDS_REVIEW')] if live else []