
#!/usr/bin/env python3
"""
CSRF Attack Tester (Enhanced with Exploitation Mode for WordPress)

Tests for CSRF vulnerabilities and attempts controlled exploitation for critical issues.
For educational purposes only - use only on websites you own or have permission to test.
"""

import sys
import argparse
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import os
import time
from colorama import init, Fore, Style
import json
import re
import hashlib
import uuid

# Initialize colorama
init()

class CSRFAttackTester:
    def __init__(self, target_url, output_dir="csrf_tests", verbose=False, timeout=10, safe_mode=False, exploit=False):
        """
        Initialize the CSRF attack tester.

        Args:
            target_url: The base URL of the website to test
            output_dir: Directory to save test results and PoCs
            verbose: Whether to show detailed output
            timeout: Request timeout in seconds
            safe_mode: Run in safe mode to avoid generating exploitable PoCs
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
        self.results = []
        self.forms_tested = 0
        self.vulnerabilities_found = 0
        self.exploits_successful = 0
        self.form_hashes = set()
        self.known_form_plugins = {
            'sureforms': {'name': 'SureForms', 'fix': 'Enable CSRF protection in SureForms settings or add wp_nonce_field().'},
            'forminator': {'name': 'Forminator', 'fix': 'Ensure nonce validation in Forminator settings.'},
            'woocommerce': {'name': 'WooCommerce', 'fix': 'Add wp_nonce_field() to WooCommerce templates.'}
        }

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

    def normalize_url(self, url):
        """Normalize URL to avoid duplicates."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def hash_form(self, form):
        """Generate a unique hash for a form based on its inputs."""
        inputs = sorted([f"{i.get('name')}:{i.get('value')}" for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')])
        form_string = ''.join(inputs) + form.get('action', '') + form.get('method', '')
        return hashlib.md5(form_string.encode()).hexdigest()

    def crawl_page(self, url, visited=None):
        """Crawl a page to find forms and links."""
        if visited is None:
            visited = set()

        normalized_url = self.normalize_url(url)
        if normalized_url in visited:
            return []

        visited.add(normalized_url)
        forms = []
        links = []

        try:
            self.log(f"Crawling {url}...")
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find forms
            for form in soup.find_all('form'):
                form_hash = self.hash_form(form)
                if form_hash not in self.form_hashes:
                    self.form_hashes.add(form_hash)
                    forms.append({'url': url, 'form': form})

            # Find links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(self.target_url, href)
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    links.append(full_url)

        except requests.RequestException as e:
            self.log(f"Error crawling {url}: {e}", "error")

        return forms, links

    def crawl_site(self, max_pages=10):
        """Crawl the site to find forms."""
        forms = []
        links_to_crawl = [self.target_url]
        visited = set()
        wordpress_endpoints = [
            '/wp-login.php', '/', '/cart/', '/checkout/', '/my-account/',
            '/contact/', '/register/'
        ]

        # Add WordPress-specific endpoints
        for endpoint in wordpress_endpoints:
            full_url = urljoin(self.target_url, endpoint)
            if self.normalize_url(full_url) not in [self.normalize_url(l) for l in links_to_crawl]:
                links_to_crawl.append(full_url)

        while links_to_crawl and len(visited) < max_pages:
            url = links_to_crawl.pop(0)
            page_forms, new_links = self.crawl_page(url, visited)
            forms.extend(page_forms)
            for link in new_links:
                if self.normalize_url(link) not in visited and self.normalize_url(link) not in [self.normalize_url(l) for l in links_to_crawl]:
                    links_to_crawl.append(link)
            time.sleep(0.5)  # Rate-limiting

        return forms

    def detect_form_plugin(self, form):
        """Detect form plugin based on form attributes."""
        form_id = form.get('id', '')
        form_class = ' '.join(form.get('class', []))
        inputs = [i.get('name', '') for i in form.find_all('input')]

        if 'sureforms' in form_id.lower() or 'sureforms' in form_class.lower() or any('sureforms' in i.lower() for i in inputs):
            return 'sureforms'
        if 'forminator' in form_id.lower() or 'forminator' in form_class.lower() or any('forminator' in i.lower() for i in inputs):
            return 'forminator'
        if 'woocommerce' in form_id.lower() or 'woocommerce' in form_class.lower() or any('woocommerce' in i.lower() for i in inputs) or any(i.startswith('billing_') or i.startswith('shipping_') or i.startswith('order_') for i in inputs):
            return 'woocommerce'
        return None

    def attempt_exploit(self, url, action_url, method, inputs, plugin):
        """Attempt to exploit a CSRF vulnerability with dummy data."""
        exploit_result = {
            'success': False,
            'details': '',
            'response_code': None,
            'security_headers': [],
            'form_type': 'Unknown',
            'protection_mechanisms': [],
            'diagnostic_info': {}
        }

        # Determine form type for better context
        form_type = "Unknown"
        if any('login' in i['name'].lower() for i in inputs if i.get('name')):
            form_type = "Login Form"
        elif any('password' in i['name'].lower() for i in inputs if i.get('name')):
            form_type = "Password/Account Form"
        elif any('checkout' in i['name'].lower() for i in inputs if i.get('name')):
            form_type = "Checkout Form"
        elif any('s' == i['name'].lower() for i in inputs if i.get('name')):
            form_type = "Search Form"
        elif any('comment' in i['name'].lower() for i in inputs if i.get('name')):
            form_type = "Comment Form"
        elif plugin:
            form_type = f"{plugin.capitalize()} Form"

        exploit_result['form_type'] = form_type

        try:
            # Create dummy data for the form
            test_data = {}
            for input_field in inputs:
                name = input_field['name']
                if 'nonce' in name.lower():
                    continue
                if 'email' in name.lower():
                    test_data[name] = f"test-{uuid.uuid4()}@example.com"
                elif 'name' in name.lower():
                    test_data[name] = "Test User"
                elif 'subject' in name.lower():
                    test_data[name] = "Test Subject"
                elif 'message' in name.lower():
                    test_data[name] = "This is a test CSRF exploit attempt."
                elif name == 's':  # Search forms
                    test_data[name] = "test"
                else:
                    test_data[name] = input_field['value'] or "test"

            exploit_result['diagnostic_info']['test_data'] = test_data

            # First, check for existing security headers
            try:
                head_response = self.session.head(action_url, timeout=self.timeout)
                security_headers = []
                protection_mechanisms = []

                # Check for security headers
                if 'X-Frame-Options' in head_response.headers:
                    security_headers.append(f"X-Frame-Options: {head_response.headers['X-Frame-Options']}")
                    protection_mechanisms.append("Clickjacking Protection")

                if 'Content-Security-Policy' in head_response.headers:
                    security_headers.append("Content-Security-Policy (CSP)")
                    protection_mechanisms.append("Content Security Policy")

                if 'X-XSS-Protection' in head_response.headers:
                    security_headers.append(f"X-XSS-Protection: {head_response.headers['X-XSS-Protection']}")
                    protection_mechanisms.append("XSS Protection")

                if 'Set-Cookie' in head_response.headers:
                    cookies = head_response.headers.get('Set-Cookie', '')
                    if 'SameSite' in cookies:
                        security_headers.append("SameSite Cookie Attribute")
                        protection_mechanisms.append("SameSite Cookies")
                    if 'Secure' in cookies:
                        security_headers.append("Secure Cookie Attribute")
                        protection_mechanisms.append("Secure Cookies")
                    if 'HttpOnly' in cookies:
                        security_headers.append("HttpOnly Cookie Attribute")
                        protection_mechanisms.append("HttpOnly Cookies")

                exploit_result['security_headers'] = security_headers
                exploit_result['protection_mechanisms'] = protection_mechanisms

            except requests.RequestException:
                pass  # Continue with the exploit attempt even if header check fails

            # Submit the form
            self.log(f"Attempting CSRF exploit on {url} ({form_type}) with action {action_url}...", "exploit")

            # Store original cookies and referer for comparison
            original_cookies = self.session.cookies.copy()
            original_referer = self.session.headers.get('Referer')

            # Set a different referer to simulate cross-site request
            self.session.headers.update({'Referer': 'https://attacker-site.example.com'})

            if method.lower() == 'post':
                response = self.session.post(action_url, data=test_data, timeout=self.timeout, allow_redirects=True)
            else:
                response = self.session.get(action_url, params=test_data, timeout=self.timeout, allow_redirects=True)

            # Restore original referer
            if original_referer:
                self.session.headers.update({'Referer': original_referer})
            else:
                self.session.headers.pop('Referer', None)

            # Check for cookie changes which might indicate session state changes
            cookie_changes = []
            for cookie in self.session.cookies:
                if cookie.name not in [c.name for c in original_cookies] or \
                   cookie.value != original_cookies.get(cookie.name, None):
                    cookie_changes.append(f"{cookie.name} changed")

            exploit_result['diagnostic_info']['cookie_changes'] = cookie_changes

            # Analyze response for common protection patterns
            protection_indicators = []
            if 'csrf' in response.text.lower():
                protection_indicators.append("CSRF term found in response")
            if 'security' in response.text.lower() and ('error' in response.text.lower() or 'invalid' in response.text.lower()):
                protection_indicators.append("Security error message found")
            if 'nonce' in response.text.lower() and ('error' in response.text.lower() or 'invalid' in response.text.lower()):
                protection_indicators.append("Nonce validation message found")
            if 'token' in response.text.lower() and ('error' in response.text.lower() or 'invalid' in response.text.lower()):
                protection_indicators.append("Token validation message found")
            if 'permission' in response.text.lower() and ('error' in response.text.lower() or 'denied' in response.text.lower()):
                protection_indicators.append("Permission denied message found")

            exploit_result['diagnostic_info']['protection_indicators'] = protection_indicators

            # Check if the form action was actually processed
            action_indicators = []
            if form_type == "Search Form" and "search" in response.url.lower():
                action_indicators.append("Search results page detected")
            if form_type == "Login Form" and "login" in response.url.lower():
                action_indicators.append("Still on login page (likely failed)")
            if "thank" in response.text.lower() or "success" in response.text.lower():
                action_indicators.append("Success/thank you message detected")
            if "error" in response.text.lower() or "invalid" in response.text.lower():
                action_indicators.append("Error message detected")

            exploit_result['diagnostic_info']['action_indicators'] = action_indicators

            # Determine if the exploit was successful based on all collected data
            exploit_success = False
            success_reasons = []
            failure_reasons = []

            # Check response status
            if response.status_code in [200, 201, 302]:
                if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                    # Look for signs of successful form processing
                    if form_type == "Search Form" and "search" in response.url.lower():
                        # Search forms aren't really exploitable in a harmful way
                        exploit_success = False
                        failure_reasons.append("Search form successfully processed but not a security risk")
                    elif cookie_changes and not protection_indicators:
                        exploit_success = True
                        success_reasons.append("Form processed and cookies changed")
                    elif "success" in response.text.lower() or "thank" in response.text.lower():
                        exploit_success = True
                        success_reasons.append("Success message detected in response")
                    elif not protection_indicators and not action_indicators:
                        # No clear indicators either way
                        exploit_success = False
                        failure_reasons.append("Form processed but no clear impact detected")
                else:
                    exploit_success = False
                    failure_reasons.append("Error or invalid message in response")
            else:
                exploit_success = False
                failure_reasons.append(f"HTTP status code {response.status_code} indicates failure")

            # Special case for search forms
            if form_type == "Search Form":
                exploit_success = False
                if not failure_reasons:
                    failure_reasons.append("Search forms aren't security-sensitive even if they lack CSRF protection")

            # Special case for login forms
            if form_type == "Login Form" and not exploit_success:
                failure_reasons.append("Login forms typically have additional protections beyond nonces")

            # Update result based on our analysis
            exploit_result['success'] = exploit_success
            exploit_result['diagnostic_info']['success_reasons'] = success_reasons
            exploit_result['diagnostic_info']['failure_reasons'] = failure_reasons

            if exploit_success:
                self.log(f"Exploit succeeded on {url}! Form submission accepted.", "exploit")
                exploit_result['details'] = "Form submission accepted without nonce, confirming CSRF vulnerability."
                if success_reasons:
                    exploit_result['details'] += f" Reasons: {', '.join(success_reasons)}"
                self.exploits_successful += 1
            else:
                if failure_reasons:
                    exploit_result['details'] = f"Exploit failed. Reasons: {', '.join(failure_reasons)}"
                else:
                    exploit_result['details'] = "Form submission blocked (possible server-side validation)."

            exploit_result['response_code'] = response.status_code
            exploit_result['response_snippet'] = response.text[:500]  # Truncate for brevity
            exploit_result['final_url'] = response.url  # Capture the final URL after redirects

        except requests.RequestException as e:
            exploit_result['details'] = f"Exploit failed due to request error: {e}"
            exploit_result['diagnostic_info']['exception'] = str(e)
            self.log(f"Exploit failed on {url}: {e}", "error")

        return exploit_result

    def test_form_csrf(self, form_info):
        """Test a form for CSRF vulnerabilities."""
        url = form_info['url']
        form = form_info['form']
        issues = []

        try:
            action = form.get('action', url)
            action_url = urljoin(url, action)
            method = form.get('method', 'get').lower()
            is_woocommerce = 'my-account' in url or 'checkout' in url or 'cart' in url or self.detect_form_plugin(form) == 'woocommerce'

            # Extract form inputs
            inputs = []
            has_nonce = False
            nonce_name = None
            for input_field in form.find_all(['input', 'textarea', 'select']):
                name = input_field.get('name')
                value = input_field.get('value', '')
                if name:
                    inputs.append({'name': name, 'value': value})
                    if name == '_wpnonce' or 'nonce' in name.lower():
                        has_nonce = True
                        nonce_name = name

            # Detect form plugin
            plugin = self.detect_form_plugin(form)

            # Check for WordPress nonce
            if has_nonce:
                self.log(f"Form at {url} has a nonce ({nonce_name}), testing validation...", "success")

                # Test nonce validation
                test_data = {i['name']: i['value'] for i in inputs if i['name'] != nonce_name}
                try:
                    response = self.session.post(action_url, data=test_data, timeout=self.timeout, allow_redirects=False)
                    if response.status_code == 200 and 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                        self.log(f"Form at {url} accepted submission without nonce, vulnerable!", "vuln")
                        issues.append({
                            'issue': 'Nonce not validated',
                            'description': f'The form at {url} accepted a submission without the {nonce_name} field, indicating weak CSRF protection.',
                            'severity': 'High' if is_woocommerce else 'Medium',
                            'form_action': action_url,
                            'method': method,
                            'inputs': inputs,
                            'plugin': plugin
                        })
                        self.vulnerabilities_found += 1
                    else:
                        issues.append({
                            'issue': 'Form likely protected by nonce',
                            'description': f'The form contains a {nonce_name} field, and submission without it was blocked, indicating CSRF protection.',
                            'severity': 'Info',
                            'form_action': action_url,
                            'method': method,
                            'inputs': inputs,
                            'plugin': plugin
                        })
                except requests.RequestException as e:
                    self.log(f"Error testing nonce validation at {url}: {e}", "error")

                # Test with fake nonce
                test_data = {i['name']: i['value'] for i in inputs}
                test_data[nonce_name] = 'fake_nonce'
                try:
                    response = self.session.post(action_url, data=test_data, timeout=self.timeout, allow_redirects=False)
                    if response.status_code == 200 and 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                        self.log(f"Form at {url} accepted fake nonce, vulnerable!", "vuln")
                        issues.append({
                            'issue': 'Fake nonce accepted',
                            'description': f'The form at {url} accepted a fake {nonce_name} value, indicating weak CSRF protection.',
                            'severity': 'High' if is_woocommerce else 'Medium',
                            'form_action': action_url,
                            'method': method,
                            'inputs': inputs,
                            'plugin': plugin
                        })
                        self.vulnerabilities_found += 1
                except requests.RequestException as e:
                    self.log(f"Error testing fake nonce at {url}: {e}", "error")
            else:
                severity = 'Critical' if is_woocommerce else 'High'
                self.log(f"Form at {url} lacks a WordPress nonce, vulnerable to CSRF.", "vuln")
                issue = {
                    'issue': 'Missing WordPress nonce',
                    'description': 'The form lacks a _wpnonce field, making it vulnerable to CSRF attacks.',
                    'severity': severity,
                    'form_action': action_url,
                    'method': method,
                    'inputs': inputs,
                    'plugin': plugin
                }

                # Attempt exploitation if critical and exploit mode is enabled
                if self.exploit and severity == 'Critical':
                    exploit_result = self.attempt_exploit(url, action_url, method, inputs, plugin)
                    issue['exploit_attempted'] = True
                    issue['exploit_success'] = exploit_result['success']
                    issue['exploit_details'] = exploit_result['details']
                    issue['exploit_response_code'] = exploit_result['response_code']
                    issue['exploit_response_snippet'] = exploit_result.get('response_snippet', '')

                    # Add new diagnostic information
                    issue['form_type'] = exploit_result.get('form_type', 'Unknown')
                    issue['security_headers'] = exploit_result.get('security_headers', [])
                    issue['protection_mechanisms'] = exploit_result.get('protection_mechanisms', [])
                    issue['diagnostic_info'] = exploit_result.get('diagnostic_info', {})
                    issue['final_url'] = exploit_result.get('final_url', '')

                issues.append(issue)
                self.vulnerabilities_found += 1

                # Generate PoC
                if not self.safe_mode:
                    self.generate_poc(url, action_url, method, inputs, plugin)

        except Exception as e:
            self.log(f"Error testing form at {url}: {e}", "error")

        return issues

    def generate_poc(self, source_url, action_url, method, inputs, plugin):
        """Generate a CSRF PoC HTML file."""
        poc_filename = f"{self.output_dir}/csrf_poc_{source_url.replace('://', '_').replace('/', '_')}_{time.time()}.html"
        try:
            with open(poc_filename, 'w', encoding='utf-8') as f:
                f.write("<!DOCTYPE html>\n")
                f.write("<html lang='en'>\n<head>\n")
                f.write("<meta charset='UTF-8'>\n")
                f.write(f"<title>CSRF PoC for {source_url}</title>\n")
                f.write("<style>body { font-family: Arial, sans-serif; margin: 20px; } .warning { color: red; }</style>\n")
                f.write("</head>\n<body>\n")
                f.write(f"<h1>CSRF Proof of Concept</h1>\n")
                f.write(f"<p><strong>Target URL:</strong> {source_url}</p>\n")
                f.write(f"<p><strong>Form Action:</strong> {action_url}</p>\n")
                f.write(f"<p><strong>Method:</strong> {method.upper()}</p>\n")
                if plugin:
                    f.write(f"<p><strong>Form Plugin:</strong> {self.known_form_plugins[plugin]['name']}</p>\n")
                f.write("<p class='warning'>WARNING: This is a PoC for educational purposes only. Do not use maliciously.</p>\n")
                f.write("<h2>Manual CSRF Form</h2>\n")
                f.write(f"<form action='{action_url}' method='{method}'>\n")
                for input_field in inputs:
                    if 'nonce' not in input_field['name'].lower():
                        f.write(f"  <input type='text' name='{input_field['name']}' value='test'><br>\n")
                f.write("  <br><input type='submit' value='Submit CSRF'>\n")
                f.write("</form>\n")
                if self.safe_mode:
                    f.write("<h2>Safe Testing Instructions</h2>\n")
                    f.write("<p>Manually test by submitting the form in a browser with developer tools to confirm CSRF vulnerability.</p>\n")
                f.write("</body>\n</html>\n")

            self.log(f"CSRF PoC saved to {poc_filename}", "success")

        except Exception as e:
            self.log(f"Error generating PoC for {source_url}: {e}", "error")

    def detect_security_plugins(self):
        """Detect common WordPress security plugins."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            plugins = []
            if 'wordfence' in response.text.lower():
                plugins.append('Wordfence')
            if 'ithemes-security' in response.text.lower() or 'better-wp-security' in response.text.lower():
                plugins.append('iThemes Security')
            if soup.find('meta', {'name': 'generator', 'content': re.compile('loginizer', re.I)}):
                plugins.append('Loginizer')
            return plugins
        except requests.RequestException:
            return []

    def run(self):
        """Run CSRF tests."""
        self.log(f"Starting CSRF tests for {self.target_url}...")
        if self.exploit:
            self.log("Exploit mode enabled: Attempting to exploit critical vulnerabilities.", "warning")

        # Detect security plugins
        security_plugins = self.detect_security_plugins()
        if security_plugins:
            self.log(f"Detected security plugins: {', '.join(security_plugins)}. Tests may be affected.", "warning")

        # Crawl site for forms
        forms = self.crawl_site()
        self.log(f"Found {len(forms)} unique forms to test.")

        # Test each form
        for form_info in forms:
            issues = self.test_form_csrf(form_info)
            self.results.append({
                'url': form_info['url'],
                'issues': issues
            })
            self.forms_tested += 1
            time.sleep(0.5)  # Rate-limiting

        # Generate summary
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Info': 0}
        for result in self.results:
            for issue in result['issues']:
                severity_counts[issue['severity']] += 1

        self.log(f"CSRF testing completed. Tested {self.forms_tested} forms, found {self.vulnerabilities_found} potential vulnerabilities:", "info")
        self.log(f"Critical: {severity_counts['Critical']}", "error" if severity_counts['Critical'] > 0 else "info")
        self.log(f"High: {severity_counts['High']}", "error" if severity_counts['High'] > 0 else "info")
        self.log(f"Medium: {severity_counts['Medium']}", "warning" if severity_counts['Medium'] > 0 else "info")
        self.log(f"Info: {severity_counts['Info']}", "info")
        if self.exploit:
            self.log(f"Successful exploits: {self.exploits_successful}", "exploit" if self.exploits_successful > 0 else "info")

        # Save results to JSON
        results_file = f"{self.output_dir}/csrf_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        self.log(f"Results saved to {results_file}", "success")

        # Generate WordPress-specific report
        report_file = f"{self.output_dir}/csrf_report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# CSRF Vulnerability Report for WordPress\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"## Summary\n\n")
            f.write(f"- Forms tested: {self.forms_tested}\n")
            f.write(f"- Potential vulnerabilities found: {self.vulnerabilities_found}\n")
            f.write(f"- Critical: {severity_counts['Critical']}\n")
            f.write(f"- High: {severity_counts['High']}\n")
            f.write(f"- Medium: {severity_counts['Medium']}\n")
            f.write(f"- Info: {severity_counts['Info']}\n")
            if self.exploit:
                f.write(f"- Successful exploits: {self.exploits_successful}\n")
            if security_plugins:
                f.write(f"- Detected security plugins: {', '.join(security_plugins)}\n")
            f.write("\n")

            f.write(f"## Form Status Table\n\n")
            f.write("| URL | Plugin | Form Type | Nonce Present | Severity | Exploit Status | Protection Mechanisms |\n")
            f.write("|-----|--------|-----------|---------------|----------|----------------|------------------------|\n")
            for result in self.results:
                url = result['url']
                for issue in result['issues']:
                    plugin = self.known_form_plugins.get(issue.get('plugin', ''), {}).get('name', 'Unknown')
                    nonce = '✓' if issue['severity'] == 'Info' else '✗'

                    # Get form type
                    form_type = issue.get('form_type', 'Unknown')

                    # Get exploit status with reason
                    if issue.get('exploit_attempted', False):
                        if issue.get('exploit_success', False):
                            exploit = '✓ Success'
                        else:
                            # Get the first failure reason if available
                            failure_reasons = issue.get('diagnostic_info', {}).get('failure_reasons', [])
                            reason = failure_reasons[0] if failure_reasons else 'Failed'
                            # Truncate long reasons
                            if len(reason) > 30:
                                reason = reason[:27] + '...'
                            exploit = f'✗ ({reason})'
                    else:
                        exploit = '-'

                    # Get protection mechanisms
                    protection = ', '.join(issue.get('protection_mechanisms', []))
                    if not protection and issue.get('diagnostic_info', {}).get('protection_indicators', []):
                        protection = ', '.join(issue.get('diagnostic_info', {}).get('protection_indicators', []))
                    if len(protection) > 30:
                        protection = protection[:27] + '...'

                    f.write(f"| {url} | {plugin} | {form_type} | {nonce} | {issue['severity']} | {exploit} | {protection} |\n")

            for result in self.results:
                url = result['url']
                f.write(f"\n## Results for {url}\n\n")
                if result['issues']:
                    f.write(f"### CSRF Issues\n\n")
                    for issue in result['issues']:
                        f.write(f"#### {issue['issue']} ({issue['severity']})\n\n")
                        f.write(f"- **Form Action**: {issue['form_action']}\n")
                        f.write(f"- **Method**: {issue['method'].upper()}\n")
                        f.write(f"- **Description**: {issue['description']}\n")
                        if issue.get('plugin'):
                            f.write(f"- **Plugin**: {self.known_form_plugins[issue['plugin']]['name']}\n")
                            f.write(f"- **Fix**: {self.known_form_plugins[issue['plugin']]['fix']}\n")
                        else:
                            f.write(f"- **Fix**: Add a WordPress nonce with `wp_nonce_field()` in the form.\n")
                        if issue.get('exploit_attempted', False):
                            f.write(f"- **Exploit Attempted**: {'Successful' if issue['exploit_success'] else 'Failed'}\n")
                            f.write(f"- **Exploit Details**: {issue['exploit_details']}\n")
                            f.write(f"- **Response Code**: {issue['exploit_response_code']}\n")

                            # Add form type information
                            if issue.get('form_type'):
                                f.write(f"- **Form Type**: {issue['form_type']}\n")

                            # Add security headers information
                            if issue.get('security_headers'):
                                f.write(f"- **Security Headers**: {', '.join(issue['security_headers'])}\n")

                            # Add protection mechanisms information
                            if issue.get('protection_mechanisms'):
                                f.write(f"- **Protection Mechanisms**: {', '.join(issue['protection_mechanisms'])}\n")

                            # Add diagnostic information
                            if issue.get('diagnostic_info'):
                                f.write(f"- **Diagnostic Information**:\n")

                                # Add failure reasons
                                if issue['diagnostic_info'].get('failure_reasons'):
                                    f.write(f"  - **Failure Reasons**: {', '.join(issue['diagnostic_info']['failure_reasons'])}\n")

                                # Add success reasons
                                if issue['diagnostic_info'].get('success_reasons'):
                                    f.write(f"  - **Success Reasons**: {', '.join(issue['diagnostic_info']['success_reasons'])}\n")

                                # Add protection indicators
                                if issue['diagnostic_info'].get('protection_indicators'):
                                    f.write(f"  - **Protection Indicators**: {', '.join(issue['diagnostic_info']['protection_indicators'])}\n")

                                # Add action indicators
                                if issue['diagnostic_info'].get('action_indicators'):
                                    f.write(f"  - **Action Indicators**: {', '.join(issue['diagnostic_info']['action_indicators'])}\n")

                                # Add cookie changes
                                if issue['diagnostic_info'].get('cookie_changes'):
                                    f.write(f"  - **Cookie Changes**: {', '.join(issue['diagnostic_info']['cookie_changes'])}\n")

                            # Add final URL after redirects
                            if issue.get('final_url'):
                                f.write(f"- **Final URL**: {issue['final_url']}\n")

                            f.write(f"- **Response Snippet**: {issue['exploit_response_snippet']}\n")
                        f.write("\n")
                else:
                    f.write("No CSRF issues found.\n\n")

            # Add a new section explaining exploit results
            f.write(f"## Exploit Analysis\n\n")

            # Count exploits by status and reason
            exploit_attempts = 0
            exploit_successes = 0
            exploit_failures = 0
            failure_reasons = {}
            success_reasons = {}
            protection_mechanisms_found = set()

            for result in self.results:
                for issue in result['issues']:
                    if issue.get('exploit_attempted', False):
                        exploit_attempts += 1
                        if issue.get('exploit_success', False):
                            exploit_successes += 1
                            for reason in issue.get('diagnostic_info', {}).get('success_reasons', []):
                                success_reasons[reason] = success_reasons.get(reason, 0) + 1
                        else:
                            exploit_failures += 1
                            for reason in issue.get('diagnostic_info', {}).get('failure_reasons', []):
                                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

                        # Collect protection mechanisms
                        for mech in issue.get('protection_mechanisms', []):
                            protection_mechanisms_found.add(mech)

            f.write(f"### Exploit Summary\n\n")
            f.write(f"- **Total Exploit Attempts**: {exploit_attempts}\n")
            f.write(f"- **Successful Exploits**: {exploit_successes}\n")
            f.write(f"- **Failed Exploits**: {exploit_failures}\n\n")

            if failure_reasons:
                f.write(f"### Why Exploits Failed\n\n")
                for reason, count in failure_reasons.items():
                    f.write(f"- **{reason}**: {count} occurrence(s)\n")
                f.write("\n")

            if success_reasons:
                f.write(f"### Why Exploits Succeeded\n\n")
                for reason, count in success_reasons.items():
                    f.write(f"- **{reason}**: {count} occurrence(s)\n")
                f.write("\n")

            if protection_mechanisms_found:
                f.write(f"### Protection Mechanisms Detected\n\n")
                for mech in sorted(protection_mechanisms_found):
                    f.write(f"- {mech}\n")
                f.write("\n")

            f.write(f"### Explanation of Results\n\n")
            f.write("The CSRF test results should be interpreted carefully:\n\n")
            f.write("1. **False Positives**: Some forms (like search forms) may lack nonces but aren't security risks\n")
            f.write("2. **Alternative Protections**: Forms may use other security measures like SameSite cookies or referer checking\n")
            f.write("3. **Login Forms**: WordPress login forms have additional protections beyond nonces\n")
            f.write("4. **Search Forms**: These aren't security-sensitive even without CSRF protection\n")
            f.write("5. **Failed Exploits**: A failed exploit attempt usually indicates other security measures are working\n\n")

            f.write(f"## WordPress-Specific Recommendations\n\n")
            f.write("1. **Add Nonces to Forms**: Ensure all forms have a `_wpnonce` field:\n")
            f.write("    ```php\n    wp_nonce_field('action_name', '_wpnonce');\n    ```\n")
            f.write("2. **Validate Nonces**: Check nonces on submission:\n")
            f.write("    ```php\n    if (!wp_verify_nonce($_POST['_wpnonce'], 'action_name')) { wp_die('CSRF check failed'); }\n    ```\n")
            f.write("3. **Secure Cookies**: Set SameSite attribute:\n")
            f.write("    ```php\n    @ini_set('session.cookie_samesite', 'Lax');\n    ```\n")
            f.write("4. **Use Security Plugins**: Install iThemes Security to add nonces automatically.\n")
            f.write("5. **WooCommerce**: Ensure my-account and checkout forms have nonces in `woocommerce/templates/`.\n")
            f.write("6. **Test Exploits Safely**: Use generated PoCs in a staging environment to confirm vulnerabilities.\n")

        self.log(f"Report saved to {report_file}", "success")
        return self.results

def main():
    """Main function to run the CSRF attack tester."""
    parser = argparse.ArgumentParser(description="CSRF Attack Tester (WordPress Enhanced)")
    parser.add_argument("url", help="Target WordPress URL to test")
    parser.add_argument("-o", "--output", default="csrf_tests", help="Output directory for test results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode to avoid generating exploitable PoCs")
    parser.add_argument("--exploit", action="store_true", help="Attempt to exploit critical vulnerabilities")
    args = parser.parse_args()

    print(f"{Fore.CYAN}CSRF Attack Tester (WordPress Enhanced with Exploitation Mode){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test. Exploitation mode may trigger security plugins.{Style.RESET_ALL}\n")

    tester = CSRFAttackTester(
        args.url, args.output, args.verbose, args.timeout, args.safe_mode, args.exploit
    )
    tester.run()

if __name__ == "__main__":
    main()
