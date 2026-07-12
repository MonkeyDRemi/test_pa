from dataclasses import dataclass

@dataclass
class Vulnerability:
    file: str
    line: int
    column: int
    rule_id: str
    severity: str
    description: str