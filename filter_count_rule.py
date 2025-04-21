from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class FilterCountRule(Rule):
    id = 'GFILTER_COUNT'
    description = 'Worksheets using too many filters (>10).'
    group = 'Performance'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for ws in tree.findall('.//worksheet'):
            filters = ws.findall('.//filter')
            if len(filters) > 10:
                findings.append(Finding(self.id,
                    f"Worksheet '{ws.get('name')}' has {len(filters)} filters."
                    , 'NEEDS_REVIEW'))
        return findings