from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class WorkbookDescriptionRule(Rule):
    id = 'GDESC'
    description = 'Require descriptions/captions for workbook & sheets.'
    group = 'Documentation'
    severity = 'LOW'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings: list[Finding] = []
        wb = tree.find('.//workbook')
        if wb is not None and not (wb.get('description') or '').strip():
            findings.append(Finding(self.id,
                'Workbook is missing a description.', 'TAKE_ACTION'))
        for ws in tree.findall('.//worksheet'):
            if not ((ws.get('caption') or '').strip() or (ws.get(
                'description') or '').strip()):
                findings.append(Finding(self.id,
                    f"Worksheet '{ws.get('name')}' is missing caption or description."
                    , 'TAKE_ACTION'))
        for dash in tree.findall('.//dashboard'):
            if not (dash.get('description') or '').strip():
                findings.append(Finding(self.id,
                    f"Dashboard '{dash.get('name')}' is missing a description."
                    , 'TAKE_ACTION'))
        return findings