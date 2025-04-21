from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class CrossDataSourceCalcRule(Rule):
    id = 'GCROSS_DS'
    description = 'Detect calculations that span data sources.'
    group = 'Performance'
    severity = 'HIGH'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        cross = tree.findall('.//calculation[@is-cross-data-source="true"]')
        return [Finding(self.id,
            'Workbook contains cross‑data‑source calculations.',
            'NEEDS_REVIEW')] if cross else []