# rule_base.py

import xml.etree.ElementTree as ET
from typing import List

class Finding:
    """Represents a single rule violation (or informational message)."""

    def __init__(self, rule: str, message: str, category: str):
        self.rule     = rule      # Rule ID (e.g. GBLEND)
        self.message  = message   # Human-readable finding message
        self.category = category  # TAKE_ACTION | NEEDS_REVIEW

    def __repr__(self) -> str:
        return f"<Finding {self.rule}: {self.message[:40]} …>"

class Rule:
    """Abstract base class for all workbook rules."""

    id: str          = "RULE"
    description: str = ""
    group: str       = "Uncategorized"
    severity: str    = "MEDIUM"  # INFO | LOW | MEDIUM | HIGH

    def check(self, tree: ET.ElementTree) -> List[Finding]:
        """Return a list of findings for the given workbook XML tree."""
        raise NotImplementedError()
