# sniffcat

Python client for the [SniffCat](https://sniffcat.com/documentation/api) IP reputation and abuse reporting API.

## Features

- Fetch blacklist of suspicious IPs
- Check reputation and abuse score for any IP
- View reports about IP activity
- Report suspicious IPs (e.g., for port scanning, spam, malware, etc.)

## Installation

```sh
pip install sniffcat
```

## Usage

```python
from sniffcat import SniffCatClient

# Initialize the client with your API token
client = SniffCatClient("your_api_token")

# Example 1: Get blacklist with default confidence
blacklist = client.get_blacklist()
print("Blacklist:", blacklist)

# Example 2: Get blacklist with custom confidence
blacklist_80 = client.get_blacklist(confidence_min=80)
print("Blacklist (confidence >= 80):", blacklist_80)

# Example 3: Check reputation and abuse score for an IP
ip_info = client.check_ip("1.1.1.1")
print("IP info:", ip_info)

# Example 4: Get reports for an IP
reports = client.get_ip_reports("1.1.1.1")
print("IP reports:", reports)

# Example 5: Report an IP for port scanning with default comment
result = client.report_ip_port_scan("1.1.1.1")
print("Report result:", result)

# Example 6: Report an IP for port scanning with custom comment
result_custom = client.report_ip_port_scan("1.1.1.1", comment="Suspicious port scan detected from this IP")
print("Custom report result:", result_custom)

# Example 7: Report IP as spam (category 2) and malware (category 3)
result_multi = client.report_ip("1.2.3.4", [2, 3], comment="Spam and malware activity detected")
print("Multi-category report result:", result_multi)
```

## Categories

See all available categories at [https://sniffcat.com/documentation/categories](https://sniffcat.com/documentation/categories)

## API Documentation

See full API docs at [https://sniffcat.com/documentation/api](https://sniffcat.com/documentation/api)

## License

MIT