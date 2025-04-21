from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class UnusedDataSourceRule(Rule):
    id = 'GUNUSED_DS'
    description = 'Data sources present but not referenced by any sheet.'
    group = 'Data Hygiene'
    severity = 'LOW'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for ds in tree.findall('.//datasource'):
            if ds.get('isUsed', 'true') == 'false':
                findings.append(Finding(self.id,
                    f"Datasource '{ds.get('name')}' is unused.", 'TAKE_ACTION')
                    )
        return findings