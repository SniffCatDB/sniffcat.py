import requests

# Base URL for the Sniffcat API
API_BASE = "https://api.sniffcat.com/api/v1"
# Your API token from https://sniffcat.com/api
TOKEN = "token from https://sniffcat.com/api"

# Common headers for authentication and content type
HEADERS = {
    "X-Secret-Token": TOKEN,
    "Content-Type": "application/json"
}

def get_blacklist(confidence_min=50):
    """Fetch blacklist with minimum confidence.
    Returns a list of blacklisted IPs with confidence >= confidence_min.
    """
    response = requests.get(API_BASE + "/blacklist", headers=HEADERS, params={"confidenceMin": confidence_min})
    print("Raw response:", response.text)  # Debug print
    try:
        return response.json()
    except Exception as e:
        # Handle JSON decoding errors
        print("JSON decode error:", e)
        return {"error": "Invalid JSON", "content": response.text}

def check_ip(ip):
    """Check abuse score for a single IP.
    Returns abuse information for the given IP address.
    """
    response = requests.get(API_BASE + "/check", headers=HEADERS, params={"ip": ip})
    return response.json()

def get_ip_reports(ip):
    """Get reports for a single IP, handle 404 if not found.
    Returns report data or a message if the IP is not found.
    """
    response = requests.get(API_BASE + "/reports", headers=HEADERS, params={"ip": ip})
    if response.status_code == 404:
        # IP not found in the reports database
        return {"success": False, "message": "IP not found.", "reports": None}
    return response.json()

def report_ip_port_scan(ip, comment="TCP/UDP port scanning detected"):
    """Report an IP as port_scan using category ID [4].
    Sends a report for the given IP with a comment.
    Handles rate limiting (HTTP 429).
    """
    data = {"ip": ip, "category": [4], "comment": comment}
    response = requests.post(API_BASE + "/report", headers=HEADERS, json=data)

    # Handle rate limit response
    if response.status_code == 429:
        data_resp = response.json()
        wait_time = data_resp.get("message", "")
        return {"success": False, "message": f"Rate limit exceeded: {wait_time}"}

    return response.json()


# --- Example usage ---
if __name__ == "__main__":
    # Fetch and print blacklist with minimum confidence 50
    print("BLACKLIST:")
    print(get_blacklist(confidence_min=50))

    test_ip = "1.1.1.1"
    # Check abuse score for test_ip
    print(f"\nCHECK IP: {test_ip}")
    print(check_ip(test_ip))

    # Get reports for test_ip
    print(f"\nIP REPORTS: {test_ip}")
    print(get_ip_reports(test_ip))

    report_ip = "1.1.1.1"
    # Report report_ip for port scanning
    print(f"\nREPORT IP: {report_ip}")
    print(report_ip_port_scan(report_ip))