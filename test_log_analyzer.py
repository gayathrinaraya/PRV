import pytest
from log_analyzer import LogAnalyzer
import os
import csv

@pytest.fixture
def sample_log():
    # Create a temporary log file for testing
    content = '''192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256'''
    
    with open('test.log', 'w') as f:
        f.write(content)
    yield 'test.log'
    os.remove('test.log')

def test_parse_log_line():
    analyzer = LogAnalyzer('dummy.log')
    line = '192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512'
    ip, endpoint, status = analyzer.parse_log_line(line)
    
    assert ip == '192.168.1.1'
    assert endpoint == '/home'
    assert status == 200

def test_analyze_logs(sample_log):
    analyzer = LogAnalyzer(sample_log)
    analyzer.analyze_logs()
    
    assert analyzer.ip_requests['192.168.1.1'] == 1
    assert analyzer.endpoint_access['/home'] == 1
    assert analyzer.failed_logins['203.0.113.5'] == 1

def test_suspicious_ips(sample_log):
    analyzer = LogAnalyzer(sample_log, failed_login_threshold=1)
    analyzer.analyze_logs()
    suspicious = analyzer.get_suspicious_ips()
    
    assert '203.0.113.5' in suspicious
    assert suspicious['203.0.113.5'] == 1

def test_csv_output(sample_log):
    analyzer = LogAnalyzer(sample_log)
    analyzer.analyze_logs()
    test_csv = 'test_results.csv'
    analyzer.save_results_to_csv(test_csv)
    
    assert os.path.exists(test_csv)
    
    with open(test_csv, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert 'Section: Requests per IP' in headers
    
    os.remove(test_csv)
