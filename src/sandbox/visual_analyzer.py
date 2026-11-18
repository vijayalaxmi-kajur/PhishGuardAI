"""PhishGuardAI - Visual Brand Impersonation & Perceptual Hash Analyzer

Computes perceptual difference hashes (dHash) on rendered webpage screenshots or favicon/logo
elements to detect visual brand impersonation (e.g., page renders a Microsoft or PayPal login
portal on an unrelated or spoofed domain).
"""

import io
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, List, Tuple
from PIL import Image


@dataclass
class VisualAnalysisResult:
    """Findings from perceptual hash visual brand matching."""
    has_visual_impersonation: bool = False
    impersonated_brand: Optional[str] = None
    matched_logo_or_layout: Optional[str] = None
    similarity_score: float = 0.0
    screenshot_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_visual_impersonation": self.has_visual_impersonation,
            "impersonated_brand": self.impersonated_brand,
            "matched_logo_or_layout": self.matched_logo_or_layout,
            "similarity_score": round(self.similarity_score, 4),
            "screenshot_hash": self.screenshot_hash,
            "details": self.details,
        }


class VisualBrandAnalyzer:
    """Performs visual perceptual similarity analysis using dHash."""

    DEFAULT_HASH_SIZE: int = 8
    MATCH_DISTANCE_THRESHOLD: int = 12  # Hamming distance <= 12 out of 64 bits (~81%+ visual match)

    def __init__(self, reference_fingerprints: Optional[Dict[str, str]] = None) -> None:
        """Initialize visual analyzer.
        
        Args:
            reference_fingerprints: Optional dict of {brand_key: hex_dhash}.
        """
        # Baseline reference perceptual fingerprints for prominent brand login screens / logos
        self._fingerprints: Dict[str, str] = reference_fingerprints or {
            "microsoft_login": "8c8c4e4e0f0f3a3a",
            "paypal_portal": "3c3c7878f0f06666",
            "google_signin": "0f0f1e1e3c3c7878",
            "apple_id": "ffff0000ffff0000",
        }

    @staticmethod
    def compute_dhash(image_input: Any, hash_size: int = DEFAULT_HASH_SIZE) -> str:
        """Calculate difference hash (dHash) for an image.
        
        Args:
            image_input: PIL Image object, file path, or bytes.
            hash_size: Grid size for hash (default 8 -> 8x9 grid = 64-bit hash).
            
        Returns:
            Hexadecimal hash string representing the visual gradient.
        """
        if isinstance(image_input, (str, bytes)):
            if isinstance(image_input, bytes):
                img = Image.open(io.BytesIO(image_input))
            else:
                img = Image.open(image_input)
        elif isinstance(image_input, Image.Image):
            img = image_input
        else:
            raise ValueError("Unsupported image input type.")

        # Convert to grayscale and resize to (hash_size + 1, hash_size)
        resized = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        if hasattr(resized, "get_flattened_data"):
            pixels = list(resized.get_flattened_data())
        else:
            pixels = list(resized.getdata())

        # Compare adjacent pixels (left > right)
        diff_bits = []
        width = hash_size + 1
        for row in range(hash_size):
            for col in range(hash_size):
                idx = row * width + col
                diff_bits.append(1 if pixels[idx] > pixels[idx + 1] else 0)

        # Convert bits to hex string
        decimal_val = 0
        for bit in diff_bits:
            decimal_val = (decimal_val << 1) | bit
        hex_len = (hash_size * hash_size) // 4
        return f"{decimal_val:0{hex_len}x}"

    @staticmethod
    def hamming_distance(hash1: str, hash2: str) -> int:
        """Calculate bit distance between two hexadecimal hashes."""
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 64
        val1 = int(hash1, 16)
        val2 = int(hash2, 16)
        return bin(val1 ^ val2).count("1")

    def analyze_screenshot(
        self,
        image_input: Any,
        registered_domain: str,
        brand_expected: Optional[str] = None
    ) -> VisualAnalysisResult:
        """Compare screenshot against reference fingerprints.
        
        Args:
            image_input: Screenshot image (PIL Image, bytes, or path).
            registered_domain: Root domain hosting the page.
            brand_expected: Optional specific brand name to verify.
            
        Returns:
            VisualAnalysisResult with match details.
        """
        try:
            shot_hash = self.compute_dhash(image_input)
        except Exception as e:
            return VisualAnalysisResult(details={"error": f"Failed to compute image hash: {str(e)}"})

        best_match_brand = None
        best_match_key = None
        min_dist = 64

        for key, ref_hash in self._fingerprints.items():
            dist = self.hamming_distance(shot_hash, ref_hash)
            if dist < min_dist:
                min_dist = dist
                best_match_key = key
                best_match_brand = key.split("_")[0].capitalize()

        similarity = max(0.0, (64 - min_dist) / 64.0)

        if min_dist <= self.MATCH_DISTANCE_THRESHOLD:
            # Check if domain belongs to the brand
            reg_lower = (registered_domain or "").lower()
            brand_slug = (best_match_brand or "").lower().replace(" ", "")

            is_genuine_owner = brand_slug in reg_lower

            if not is_genuine_owner:
                return VisualAnalysisResult(
                    has_visual_impersonation=True,
                    impersonated_brand=best_match_brand,
                    matched_logo_or_layout=best_match_key,
                    similarity_score=similarity,
                    screenshot_hash=shot_hash,
                    details={
                        "hamming_distance": min_dist,
                        "threshold": self.MATCH_DISTANCE_THRESHOLD,
                        "reference_hash": self._fingerprints.get(best_match_key),
                    }
                )

        return VisualAnalysisResult(
            has_visual_impersonation=False,
            similarity_score=similarity,
            screenshot_hash=shot_hash,
            details={"min_hamming_distance": min_dist}
        )
