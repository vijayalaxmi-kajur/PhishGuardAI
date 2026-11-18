"""Unit tests for VisualBrandAnalyzer (perceptual difference hashing & visual brand matching)."""

import unittest
from PIL import Image

from src.sandbox.visual_analyzer import VisualBrandAnalyzer


class TestVisualBrandAnalyzer(unittest.TestCase):
    """Test suite for visual perceptual hashing and logo brand spoofing detection."""

    def setUp(self):
        self.analyzer = VisualBrandAnalyzer()

    def test_dhash_identical_images(self):
        """Verify identical images produce identical hashes with hamming distance 0."""
        img1 = Image.new("RGB", (100, 100), color=(255, 0, 0))
        img2 = Image.new("RGB", (100, 100), color=(255, 0, 0))

        hash1 = self.analyzer.compute_dhash(img1)
        hash2 = self.analyzer.compute_dhash(img2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(self.analyzer.hamming_distance(hash1, hash2), 0)

    def test_visual_brand_impersonation_detection(self):
        """Verify image matching reference fingerprint on unauthorized domain flags visual impersonation."""
        # Create a sample gradient image
        img = Image.new("L", (100, 100))
        for x in range(100):
            for y in range(100):
                img.putpixel((x, y), (x * 2) % 256)

        target_hash = self.analyzer.compute_dhash(img)

        # Register fingerprint for "paypal"
        custom_analyzer = VisualBrandAnalyzer(reference_fingerprints={"paypal_login": target_hash})

        # Test on unauthorized domain -> impersonation flagged!
        res_phish = custom_analyzer.analyze_screenshot(img, registered_domain="verify-update.top")
        self.assertTrue(res_phish.has_visual_impersonation)
        self.assertEqual(res_phish.impersonated_brand, "Paypal")
        self.assertEqual(res_phish.similarity_score, 1.0)

        # Test on authorized domain -> genuine owner, no impersonation!
        res_legit = custom_analyzer.analyze_screenshot(img, registered_domain="paypal.com")
        self.assertFalse(res_legit.has_visual_impersonation)


if __name__ == "__main__":
    unittest.main()

