import re
from dataclasses import dataclass

@dataclass
class ThreatSignal:
    detected: bool
    threat_type: str
    confidence: float   # 0.0 to 1.0
    evidence: str

class ThreatDetector:
    
    # Patterns that strongly suggest prompt injection
    INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+(everything|all)\s+(you('ve)?\s+been\s+told|your\s+instructions)",

    r"you\s+are\s+now\s+(a\s+)?\w+",
    r"act\s+as\s+(a\s+|an\s+)?\w+",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?\w+",
    r"your\s+(new\s+)?(role|persona|identity|purpose)\s+is",
    r"from\s+now\s+on\s+(you\s+are|act\s+as)",
    
    r"new\s+system\s+prompt",
    r"disregard\s+(your\s+)?(previous\s+)?instructions",
    r"act\s+as\s+(if\s+you('re|are)?\s+)?a\s+different",
    r"\[system\]",
    r"<\|im_start\|>",
    r"###\s*instruction",
    ]
    
    
    def scan_prompt(self, text: str) -> ThreatSignal:
        """Scan any free-text input for prompt injection."""
        text_lower = text.lower()
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return ThreatSignal(
                    detected=True,
                    threat_type="prompt_injection",
                    confidence=0.95,
                    evidence=f"Pattern matched: {pattern}"
                )
        return ThreatSignal(detected=False, threat_type="none", confidence=0.0, evidence="")