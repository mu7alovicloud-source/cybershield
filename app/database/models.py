from dataclasses import dataclass

@dataclass
class ScanResult:
    path: str
    sha256: str
    risk: int
    verdict: str
