"""Verify decision engine behavior on test cases."""
import sys
import os
sys.path.insert(0, os.path.abspath("."))

from unittest.mock import MagicMock
import numpy as np
from src.decision_engine.engine import LayeredDecisionEngine, DecisionVerdict, RiskLevel
from src.threat_intelligence.base import MultiProviderLookupResult
from src.threat_intelligence.manager import ThreatIntelligenceManager

# Setup clean mock threat intelligence manager
mock_intel = MagicMock(spec=ThreatIntelligenceManager)
mock_intel.get_configured_providers.return_value = ["MockFeed"]
mock_intel.check_url.return_value = MultiProviderLookupResult(
    url="http://mock.test",
    is_any_threat=False,
    matched_sources=[],
    results={},
    available_providers=["MockFeed"],
    degraded_providers=[],
    warnings=[],
)

# Mock model that returns very low phishing probability (0.05) to test if invalid/punycode URLs are safe
mock_model = MagicMock()
mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
mock_model.classes_ = np.array([0, 1])

engine = LayeredDecisionEngine(ml_model=mock_model, threat_intel_manager=mock_intel)

test_cases = [
    ("http://", "Bare http scheme"),
    ("https://///", "Scheme with bare slashes"),
    ("file:///etc/passwd", "file: scheme"),
    ("javascript:alert(1)", "javascript: scheme"),
    ("data:text/plain,test", "data: scheme"),
    ("", "Empty input"),
    ("   ", "Whitespace input"),
    ("https:///path/only", "Missing hostname"),
    ("http://256.256.256.256/login", "Malformed IPv4"),
    ("http://1.2.3.4.5/", "Malformed IPv4 5 octets"),
    ("http://[invalid_ipv6]/", "Malformed IPv6"),
    ("http://[:::1]/", "Malformed IPv6 colons"),
    ("http://example.com/test", "Valid HTTP"),
    ("https://example.com/test", "Valid HTTPS"),
    ("https://xn--e1afmkfd.xn--p1ai/test", "Valid single-script IDN (пример.рф)"),
    ("https://xn--pple-43d.com/login", "Mixed-script homograph spoof (аpple.com)"),
    ("https://example.com/" + "a" * 5000, "Extremely long input"),
]

for url, desc in test_cases:
    res = engine.evaluate_url(url)
    print(f"[{desc.encode('ascii', 'backslashreplace').decode('ascii')}] '{url[:30]}' -> Verdict: {res.verdict.value}, Risk: {res.risk_level.value}")
    assert res.verdict != DecisionVerdict.NO_KNOWN_THREAT or desc.startswith("Valid HTTP"), f"FAILED: {desc} was marked safe!"

print("\nAll scratch test cases behaved as expected!")
