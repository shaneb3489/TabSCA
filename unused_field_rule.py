from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class UnusedFieldRule(Rule):
    id = 'GUNUSED_FIELDS'
    description = 'Fields defined but never used in any view or calc.'
    group = 'Data Hygiene'
    severity = 'LOW'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for col in tree.findall('.//column'):
            if col.get('usage') == 'unused':
                findings.append(Finding(self.id,
                    f"Field '{col.get('name')}' defined but not used.",
                    'TAKE_ACTION'))
        return findings