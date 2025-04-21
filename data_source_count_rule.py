from __future__ import annotations
from rule_base import Rule, Finding
import xml.etree.ElementTree as ET

class DataSourceCountRule(Rule):
    id = 'GDATA_SRC_COUNT'
    description = 'Warn when workbook contains a high number of data sources.'
    group = 'Design Complexity'
    severity = 'MEDIUM'

    def check(self, tree: ET.ElementTree) ->list[Finding]:
        sources = tree.findall('.//datasource')
        return [Finding(self.id,
            f'Workbook has {len(sources)} data sources.', 'NEEDS_REVIEW')
            ] if len(sources) > 25 else []