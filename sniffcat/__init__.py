"""
sniffcat - Python client for the Sniffcat API

Easily interact with the Sniffcat IP reputation and abuse reporting API.

Features:
- Fetch blacklist of suspicious IPs
- Check reputation and abuse score for any IP
- View reports about IP activity
- Report suspicious IPs (e.g., for port scanning)

API documentation: https://sniffcat.com/documentation/api

Example usage:
--------------
from sniffcat import SniffcatClient

client = SniffcatClient("your_api_token")
print(client.get_blacklist())
print(client.check_ip("1.1.1.1"))
print(client.get_ip_reports("1.1.1.1"))
print(client.report_ip_port_scan("1.1.1.1"))
--------------
"""

import requests

__version__ = "0.1.5"
__author__ = "Dominik 'skiop' S. <"
__license__ = "MIT"

API_BASE = "https://api.sniffcat.com/api/v1"

class SniffcatClient:
    """
    Python client for the Sniffcat API.

    Args:
        token (str): Your API token from https://sniffcat.com/api

    Methods:
        get_blacklist(confidence_min=50): Fetch blacklist with minimum confidence.
        check_ip(ip): Check abuse score for a single IP.
        get_ip_reports(ip): Get reports for a single IP.
        report_ip_port_scan(ip, comment): Report an IP for port scanning (category 4).
    """

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "X-Secret-Token": self.token,
            "Content-Type": "application/json"
        }

    def get_blacklist(self, confidence_min: int = 50):
        """
        Fetch blacklist with minimum confidence.

        Args:
            confidence_min (int): Minimum confidence score (default: 50)

        Returns:
            dict: Blacklisted IPs or error info
        """
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
        """
        Check abuse score for a single IP.

        Args:
            ip (str): IP address to check

        Returns:
            dict: Abuse info or error info
        """
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
        """
        Get reports for a single IP, handle 404 if not found.

        Args:
            ip (str): IP address to get reports for

        Returns:
            dict: Report data or error info
        """
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

    def report_ip_port_scan(self, ip: str, comment: str = "TCP/UDP port scanning detected"):
        """
        Report an IP as port_scan using category ID [4].

        Args:
            ip (str): IP address to report
            comment (str): Optional comment (default: "TCP/UDP port scanning detected")

        Returns:
            dict: Report result or error info
        """
        data = {"ip": ip, "category": [4], "comment": comment}
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