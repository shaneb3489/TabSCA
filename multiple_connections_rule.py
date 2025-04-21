from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class MultipleConnectionsRule(Rule):
    id = 'GMULTI_CONN'
    description = 'Single datasource uses many DB connections.'
    group = 'Connectivity'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        findings = []
        for ds in tree.findall('.//datasource'):
            conns = ds.findall('.//connection')
            if len(conns) > 3:
                findings.append(Finding(self.id,
                    f"Datasource '{ds.get('name')}' has {len(conns)} connections."
                    , 'NEEDS_REVIEW'))
        return findings