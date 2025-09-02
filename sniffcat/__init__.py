"""
sniffcat - Python client for the SniffCat API

Features:
- Fetch blacklist of suspicious IPs
- Check reputation and abuse score for any IP
- View reports about IP activity
- Report suspicious IPs (e.g., for port scanning, spam, malware, etc.)

API documentation: https://sniffcat.com/documentation/api
Categories: https://sniffcat.com/documentation/categories

Example usage:
--------------
from sniffcat import SniffCatClient

client = SniffCatClient("your_api_token")
print(client.get_blacklist())
print(client.check_ip("1.1.1.1"))
print(client.get_ip_reports("1.1.1.1"))
print(client.report_ip_port_scan("1.1.1.1"))
print(client.report_ip("1.2.3.4", [2, 3], comment="Spam and malware activity detected"))
--------------
"""

import requests

__version__ = "0.1.8"
__author__ = "Dominik 'skiop' S."
__license__ = "MIT"

API_BASE = "https://api.sniffcat.com/api/v1"

class SniffCatClient:
    """
    Python client for the SniffCat API.
    """

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "X-Secret-Token": self.token,
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 (compatible; SniffCat.py/{__version__}; +https://github.com/SniffCatDB/sniffcat.py)"
        }

    def get_blacklist(self, confidence_min: int = 50):
        response = requests.get(
            f"{API_BASE}/blacklist",
            headers=self.headers,
            params={"confidenceMin": confidence_min}
        )
        try:
            return response.json()
        except Exception:
            return {"error": "Invalid JSON", "content": response.text}

    def check_ip(self, ip: str):
        response = requests.get(
            f"{API_BASE}/check",
            headers=self.headers,
            params={"ip": ip}
        )
        try:
            return response.json()
        except Exception:
            return {"error": "Invalid JSON", "content": response.text}

    def get_ip_reports(self, ip: str):
        response = requests.get(
            f"{API_BASE}/reports",
            headers=self.headers,
            params={"ip": ip}
        )
        if response.status_code == 404:
            return {"success": False, "message": "IP not found.", "reports": None}
        try:
            return response.json()
        except Exception:
            return {"error": "Invalid JSON", "content": response.text}

    def report_ip(self, ip: str, categories: list, comment: str = ""):
        """
        Report an IP with chosen categories.
        See: https://sniffcat.com/documentation/categories

        Args:
            ip (str): IP address to report
            categories (list): List of category IDs (e.g. [4])
            comment (str): Optional comment

        Returns:
            dict: Report result or error info
        """
        data = {"ip": ip, "categories": categories, "comment": comment}  # <-- poprawka tutaj!
        response = requests.post(
            f"{API_BASE}/report",
            headers=self.headers,
            json=data
        )
        if response.status_code == 429:
            try:
                data_resp = response.json()
                wait_time = data_resp.get("message", "")
            except Exception:
                wait_time = "unknown"
            return {"success": False, "message": f"Rate limit exceeded: {wait_time}"}
        try:
            return response.json()
        except Exception:
            return {"error": "Invalid JSON", "content": response.text}

    def report_ip_port_scan(self, ip: str, comment: str = "TCP/UDP port scanning detected"):
        """
        Shortcut for reporting port scanning (category 4).
        """
        return self.report_ip(ip, [4], comment)