import re
from collections import Counter, defaultdict
import csv
from typing import Dict, List, Tuple

class LogAnalyzer:
    def __init__(self, log_file: str, failed_login_threshold: int = 10):
        self.log_file = log_file
        self.failed_login_threshold = failed_login_threshold
        self.ip_requests = Counter()
        self.endpoint_access = Counter()
        self.failed_logins = defaultdict(int)

    def parse_log_line(self, line: str) -> Tuple[str, str, int]:
        """Extract IP, endpoint, and status code from a log line."""
        ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
        endpoint_pattern = r'"[A-Z]+ ([^"]+)'
        status_pattern = r'" (\d{3})'

        ip = re.search(ip_pattern, line)
        endpoint = re.search(endpoint_pattern, line)
        status = re.search(status_pattern, line)

        return (
            ip.group(1) if ip else "",
            endpoint.group(1) if endpoint else "",
            int(status.group(1)) if status else 0
        )

    def analyze_logs(self):
        """Process the log file and collect statistics."""
        with open(self.log_file, 'r') as f:
            for line in f:
                ip, endpoint, status = self.parse_log_line(line)
                if ip and endpoint:
                    self.ip_requests[ip] += 1
                    self.endpoint_access[endpoint] += 1
                    if status == 401:
                        self.failed_logins[ip] += 1

    def get_suspicious_ips(self) -> Dict[str, int]:
        """Return IPs with failed logins above threshold."""
        return {ip: count for ip, count in self.failed_logins.items() 
                if count >= self.failed_login_threshold}

    def save_results_to_csv(self, output_file: str = 'log_analysis_results.csv'):
        """Save analysis results to CSV file."""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write headers and sections
            writer.writerow(['Section: Requests per IP'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])

            writer.writerow([])  # Empty row for separation
            writer.writerow(['Section: Most Accessed Endpoint'])
            writer.writerow(['Endpoint', 'Access Count'])
            most_accessed = max(self.endpoint_access.items(), key=lambda x: x[1])
            writer.writerow(most_accessed)

            writer.writerow([])
            writer.writerow(['Section: Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in sorted(self.get_suspicious_ips().items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])

    def display_results(self):
        """Display analysis results in the terminal."""
        print("\n=== Requests per IP ===")
        print("IP Address           Request Count")
        print("-" * 35)
        for ip, count in sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20} {count}")

        print("\n=== Most Frequently Accessed Endpoint ===")
        most_accessed = max(self.endpoint_access.items(), key=lambda x: x[1])
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

        print("\n=== Suspicious Activity Detected ===")
        print("IP Address           Failed Login Attempts")
        print("-" * 45)
        suspicious_ips = self.get_suspicious_ips()
        if suspicious_ips:
            for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
                print(f"{ip:<20} {count}")
        else:
            print("No suspicious activity detected")

def main():
    analyzer = LogAnalyzer('sample.log')
    analyzer.analyze_logs()
    analyzer.display_results()
    analyzer.save_results_to_csv()

if __name__ == "__main__":
    main()
