# SniffCat.py

Python client for the [SniffCat](https://sniffcat.com/documentation/api) IP reputation and abuse reporting API.

## Features

- Fetch blacklist of suspicious IPs
- Check reputation and abuse score for any IP
- View reports about IP activity
- Report suspicious IPs (e.g., for port scanning)

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
```

## API Documentation

See full API docs at [https://sniffcat.com/documentation/api](https://sniffcat.com/documentation/api)

## Maintainers

- [ntxg](https://github.com/ntxg)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details