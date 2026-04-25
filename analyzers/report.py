from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Severity(Enum):
    CRITICAL = ("CRITICAL", 40)
    HIGH = ("HIGH", 20)
    MEDIUM = ("MEDIUM", 10)
    LOW = ("LOW", 5)
    INFO = ("INFO", 1)

    def __init__(self, label: str, score: int):
        self.label = label
        self.score = score

    @property
    def ansi(self) -> str:
        return {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[31m",
            "MEDIUM": "\033[33m",
            "LOW": "\033[36m",
            "INFO": "\033[37m",
        }[self.label]

    @property
    def icon(self) -> str:
        return {
            "CRITICAL": "[!!!]",
            "HIGH": "[!! ]",
            "MEDIUM": "[!  ]",
            "LOW": "[~  ]",
            "INFO": "[i  ]",
        }[self.label]


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.label,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
        }


_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Report:
    def __init__(self, ext_path: Path):
        self.ext_path = ext_path
        self.findings: List[Finding] = []
        self.metadata: dict = {}

    def add(self, finding: Finding):
        self.findings.append(finding)

    def filter_min_severity(self, min_sev: Severity):
        cutoff = _SEV_ORDER.index(min_sev)
        allowed = {s.name for s in _SEV_ORDER[: cutoff + 1]}
        self.findings = [f for f in self.findings if f.severity.name in allowed]

    def risk_score(self) -> int:
        return min(100, sum(f.severity.score for f in self.findings))

    def risk_label(self) -> str:
        s = self.risk_score()
        if s >= 70:
            return "CRITICAL RISK"
        if s >= 40:
            return "HIGH RISK"
        if s >= 20:
            return "MODERATE RISK"
        if s > 0:
            return "LOW RISK"
        return "MINIMAL RISK"

    def counts(self) -> dict:
        c = {s.name: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.name] += 1
        return c

    # ------------------------------------------------------------------ text

    def to_text(self) -> str:
        tty = sys.stdout.isatty()
        R = "\033[0m" if tty else ""
        B = "\033[1m" if tty else ""
        D = "\033[2m" if tty else ""

        def c(text: str, sev: Severity) -> str:
            return f"{sev.ansi}{text}{R}" if tty else text

        out: List[str] = []
        W = 70

        out.append("=" * W)
        out.append(f"{B}  Chrome Extension Security Auditor{R}")
        out.append("=" * W)

        m = self.metadata
        if m:
            out.append(f"  Extension : {m.get('name', 'Unknown')}")
            out.append(f"  Version   : {m.get('version', '?')}")
            out.append(f"  Manifest  : v{m.get('manifest_version', '?')}")
            if m.get("description"):
                desc = m["description"][:60] + ("..." if len(m["description"]) > 60 else "")
                out.append(f"  Desc      : {desc}")
            out.append(f"  Path      : {self.ext_path}")

        score = self.risk_score()
        label = self.risk_label()
        score_sev = (
            Severity.CRITICAL if score >= 70
            else Severity.HIGH if score >= 40
            else Severity.MEDIUM if score >= 20
            else Severity.LOW
        )
        out.append("")
        out.append(f"  Risk Score: {c(str(score) + '/100', score_sev)}  {c('[' + label + ']', score_sev)}")
        out.append("")

        counts = self.counts()
        out.append("-" * W)
        out.append(f"  FINDINGS SUMMARY")
        out.append("-" * W)
        for sev in _SEV_ORDER:
            n = counts[sev.name]
            if n:
                out.append(f"  {c(sev.icon, sev)} {c(f'{sev.label:<8}', sev)}  {n} finding{'s' if n != 1 else ''}")
        out.append(f"  {'':5} {'TOTAL':<8}  {len(self.findings)} findings")
        out.append("")

        for sev in _SEV_ORDER:
            grp = [f for f in self.findings if f.severity == sev]
            if not grp:
                continue
            out.append("=" * W)
            out.append(c(f"  {sev.label} FINDINGS ({len(grp)})", sev))
            out.append("=" * W)
            for i, finding in enumerate(grp, 1):
                out.append("")
                out.append(f"  [{i}] {B}{finding.title}{R}")
                out.append(f"      Category : {finding.category}")
                if finding.file:
                    loc = finding.file
                    if finding.line:
                        loc += f":{finding.line}"
                    out.append(f"      Location : {loc}")
                out.append(f"      {finding.description}")
                if finding.snippet:
                    out.append(f"      {D}Snippet:{R}")
                    for sl in finding.snippet.strip().splitlines():
                        out.append(f"        {D}{sl[:120]}{R}")
                if finding.recommendation:
                    out.append(f"      {B}Fix:{R} {finding.recommendation}")

        out.append("")
        out.append("=" * W)
        out.append("")
        return "\n".join(out)

    # ------------------------------------------------------------------ json

    def to_json(self) -> str:
        return json.dumps(
            {
                "metadata": self.metadata,
                "summary": {
                    "risk_score": self.risk_score(),
                    "risk_label": self.risk_label(),
                    "total_findings": len(self.findings),
                    "by_severity": self.counts(),
                },
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=2,
        )
