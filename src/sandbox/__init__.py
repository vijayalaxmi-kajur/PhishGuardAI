"""PhishGuardAI - Tier 3 Deep Sandbox & DOM Crawler Subsystem

Exports DOM analysis, perceptual visual brand matching, and deep sandbox crawler.
"""

from src.sandbox.dom_analyzer import DOMAnalyzer, DOMAnalysisResult
from src.sandbox.visual_analyzer import VisualBrandAnalyzer, VisualAnalysisResult
from src.sandbox.crawler import DeepSandboxCrawler, SandboxReport

__all__ = [
    "DOMAnalyzer",
    "DOMAnalysisResult",
    "VisualBrandAnalyzer",
    "VisualAnalysisResult",
    "DeepSandboxCrawler",
    "SandboxReport",
]

