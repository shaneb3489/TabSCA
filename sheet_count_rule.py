from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class SheetCountRule(Rule):
    id = 'GSHEETS'
    description = 'Workbook contains an unusually high number of sheets (>50).'
    group = 'Design Complexity'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        sheets = tree.findall('.//worksheet')
        return [Finding(self.id, f'Workbook has {len(sheets)} sheets.',
            'NEEDS_REVIEW')] if len(sheets) > 50 else []