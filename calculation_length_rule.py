from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class CalculationLengthRule(Rule):
    id = 'GCALC_LEN'
    description = 'Flag long/complex calculated fields.'
    group = 'Readability'
    severity = 'LOW'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for calc in tree.findall('.//calculation'):
            formula = calc.get('formula', '')
            if len(formula) > 600:
                findings.append(Finding(self.id,
                    f"Calculated field '{calc.get('name')}' formula >600 chars."
                    , 'NEEDS_REVIEW'))
        return findings