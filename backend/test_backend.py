import sys
import os
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

from main import app
from feature_extractor import extract_features
import database

client = TestClient(app)

class TestLivePhishingBackend(unittest.TestCase):

    def test_feature_extractor_legitimate(self):
        url = "https://www.google.com"
        res = extract_features(url)
        self.assertEqual(res["features"]["is_https"], 1)
        self.assertEqual(res["features"]["has_ip"], 0)
        self.assertEqual(res["features"]["count_at"], 0)

    def test_feature_extractor_phishing(self):
        url = "http://192.168.1.1/login-paypal-security-update-account/verify.php"
        res = extract_features(url)
        self.assertEqual(res["features"]["is_https"], 0)
        self.assertEqual(res["features"]["has_ip"], 1)
        self.assertGreater(res["features"]["suspicious_keywords_count"], 0)

    def test_predict_endpoint_safe(self):
        response = client.post("/api/v1/predict", json={"url": "https://www.google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["classification"], ["Safe", "Suspicious"])
        self.assertIn("risk_score", data)

    def test_predict_endpoint_phishing(self):
        url = "http://192.168.1.1/paypal-security-update-account/verify.php?claim=free"
        response = client.post("/api/v1/predict", json={"url": url})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["classification"], "Phishing")
        self.assertGreaterEqual(data["risk_score"], 60.0)

    def test_whitelist_endpoints(self):
        domain = "test-custom-domain.org"
        # Add
        res_add = client.post("/api/v1/whitelist", json={"domain": domain})
        self.assertEqual(res_add.status_code, 200)
        
        # Verify predict returns safe for whitelisted domain
        res_pred = client.post("/api/v1/predict", json={"url": f"http://{domain}/path"})
        self.assertEqual(res_pred.json()["classification"], "Safe")
        self.assertTrue(res_pred.json()["is_whitelisted"])

        # Delete
        res_del = client.delete(f"/api/v1/whitelist/{domain}")
        self.assertEqual(res_del.status_code, 200)

    def test_report_endpoint(self):
        response = client.post("/api/v1/report", json={
            "url": "http://fake-phishing-site.xyz/login",
            "comments": "Fake login form stealing passwords"
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

    def test_stats_endpoint(self):
        response = client.get("/api/v1/stats")
        self.assertEqual(response.status_code, 200)
        self.assertIn("total_scans", response.json())

if __name__ == "__main__":
    unittest.main()
