#!/usr/bin/env python3
"""
Cookie Security Tester (Enhanced for WordPress)

Tests cookie security issues on WordPress websites, including authenticated pages.
For educational purposes only - use only on websites you own or have permission to test.
"""

import sys
import argparse
import requests
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style
import json
import time
import os
from bs4 import BeautifulSoup
import re
import time

# Initialize colorama for cross-platform colored terminal output
init()

class CookieSecurityTester:
    def __init__(self, target_url, output_dir="cookie_tests", verbose=False, timeout=10, 
                 wp_username=None, wp_password=None, safe_mode=False):
        """
        Initialize the cookie security tester with WordPress-specific options.
        
        Args:
            target_url: The base URL of the website to test
            output_dir: Directory to save test results
            verbose: Whether to show detailed output
            timeout: Request timeout in seconds
            wp_username: WordPress username for authentication
            wp_password: WordPress password for authentication
            safe_mode: Run in safe mode to avoid aggressive tests
        """
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose
        self.timeout = timeout
        self.wp_username = wp_username
        self.wp_password = wp_password
        self.safe_mode = safe_mode
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        })
        self.results = []
        self.wordpress_cookies = [
            'wordpress_[a-f0-9]+', 'wordpress_sec_[a-f0-9]+', 'wordpress_logged_in_[a-f0-9]+',
            'wp-settings-[0-9]+', 'wp-settings-time-[0-9]+', 'woocommerce_cart_hash',
            'woocommerce_items_in_cart', 'wp_woocommerce_session_[a-f0-9]+'
        ]
        
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

    def verbose_log(self, message, level="info"):
        """Log messages only if verbose mode is enabled."""
        if self.verbose:
            self.log(message, level)

    def wordpress_login(self, login_url):
        """Authenticate to WordPress using provided credentials."""
        if not (self.wp_username and self.wp_password):
            self.log("No WordPress credentials provided. Skipping authentication.", "warning")
            return False

        self.log(f"Attempting WordPress login at {login_url}...")
        try:
            # Get login page to extract nonce
            response = self.session.get(login_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            nonce_input = soup.find('input', {'name': 'wpnonce'})
            nonce = nonce_input['value'] if nonce_input else None

            # Prepare login data
            login_data = {
                'log': self.wp_username,
                'pwd': self.wp_password,
                'wp-submit': 'Log In',
                'redirect_to': urljoin(self.target_url, '/wp-admin/'),
                'testcookie': '1'
            }
            if nonce:
                login_data['wpnonce'] = nonce

            # Submit login
            response = self.session.post(login_url, data=login_data, timeout=self.timeout, allow_redirects=True)
            
            # Check if login succeeded
            if 'wp-admin' in response.url and response.status_code == 200:
                self.log("WordPress login successful!", "success")
                return True
            else:
                self.log("WordPress login failed. Check credentials or security plugins.", "error")
                return False

        except requests.RequestException as e:
            self.log(f"Error during WordPress login: {e}", "error")
            return False

    def crawl_wordpress_endpoints(self):
        """Crawl key WordPress endpoints for cookie testing."""
        endpoints = [
            '/wp-admin/', '/wp-admin/profile.php', '/wp-admin/plugins.php',
            '/wp-json/wp/v2/users', '/wp-login.php', '/'
        ]
        if 'woocommerce' in self.target_url.lower() or any('woocommerce' in c for c in self.session.cookies):
            endpoints.extend(['/cart/', '/checkout/', '/my-account/'])

        urls_to_test = [self.target_url]
        for endpoint in endpoints:
            full_url = urljoin(self.target_url, endpoint)
            if full_url not in urls_to_test:
                urls_to_test.append(full_url)

        return urls_to_test

    def test_cookie_security(self, url):
        """Test cookie security for a given URL."""
        self.log(f"Testing cookie security for {url}...")
        issues = []

        try:
            response = self.session.get(url, timeout=self.timeout)
            if not self.session.cookies:
                self.log("No cookies found to test.", "warning")
                return issues

            self.log(f"Found {len(self.session.cookies)} cookies to test")
            is_https = urlparse(url).scheme == 'https'

            for cookie in self.session.cookies:
                cookie_issues = []

                # Check for Secure flag
                if not cookie.secure and is_https:
                    cookie_issues.append({
                        'issue': 'Missing Secure flag',
                        'description': 'The Secure flag ensures cookies are only sent over HTTPS. In WordPress, this protects admin and user sessions.',
                        'severity': 'Medium'
                    })

                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr('httponly'):
                    cookie_issues.append({
                        'issue': 'Missing HttpOnly flag',
                        'description': 'The HttpOnly flag prevents JavaScript access, reducing XSS risks. Critical for WordPress cookies like wordpress_logged_in_[hash].',
                        'severity': 'Medium'
                    })

                # Check for SameSite attribute
                if not cookie.has_nonstandard_attr('samesite'):
                    cookie_issues.append({
                        'issue': 'Missing SameSite attribute',
                        'description': 'The SameSite attribute prevents CSRF attacks. WordPress forms (e.g., checkout) need this.',
                        'severity': 'Medium'
                    })
                elif cookie.get_nonstandard_attr('samesite').lower() == 'none' and not cookie.secure:
                    cookie_issues.append({
                        'issue': 'SameSite=None without Secure flag',
                        'description': 'SameSite=None requires Secure flag to prevent unencrypted transmission.',
                        'severity': 'High'
                    })

                # Check for overly permissive Domain attribute
                if cookie.domain and cookie.domain.startswith('.'):
                    cookie_issues.append({
                        'issue': 'Overly permissive Domain attribute',
                        'description': f'The cookie domain {cookie.domain} may allow access from subdomains, risky for WordPress multisite.',
                        'severity': 'Low'
                    })

                # Check for WordPress-specific cookies
                is_wp_cookie = any(re.match(pattern, cookie.name) for pattern in self.wordpress_cookies)
                if is_wp_cookie and not (cookie.secure and cookie.has_nonstandard_attr('httponly')):
                    cookie_issues.append({
                        'issue': 'WordPress cookie without proper protection',
                        'description': f'WordPress cookie {cookie.name} lacks Secure or HttpOnly flags, risking session hijacking.',
                        'severity': 'High'
                    })

                # Check for sensitive information in cookie names/values
                sensitive_terms = ['session', 'auth', 'token', 'key', 'secret', 'pass', 'login', 'user', 'woocommerce']
                if any(term in cookie.name.lower() for term in sensitive_terms):
                    if not (cookie.secure and cookie.has_nonstandard_attr('httponly')):
                        cookie_issues.append({
                            'issue': 'Sensitive cookie without proper protection',
                            'description': f'Cookie {cookie.name} may contain sensitive data but lacks security attributes.',
                            'severity': 'High'
                        })

                # Check for long expiration times (skip in safe mode)
                if not self.safe_mode and cookie.expires:
                    current_time = time.time()
                    expiration_days = (cookie.expires - current_time) / (60 * 60 * 24)
                    if expiration_days > 30:
                        cookie_issues.append({
                            'issue': 'Long expiration time',
                            'description': f'Cookie expires in {int(expiration_days)} days, excessive for WordPress session cookies.',
                            'severity': 'Low'
                        })

                if cookie_issues:
                    issues.append({
                        'cookie_name': cookie.name,
                        'cookie_domain': cookie.domain,
                        'cookie_path': cookie.path,
                        'issues': cookie_issues
                    })
                    for issue in cookie_issues:
                        self.log(f"Cookie '{cookie.name}' has {issue['severity']} severity issue: {issue['issue']}", "vuln")

        except requests.RequestException as e:
            self.log(f"Error testing cookies: {e}", "error")

        return issues

    def test_session_management(self, url):
        """Test session management security."""
        self.log(f"Testing session management for {url}...")
        issues = []

        try:
            session1 = requests.Session()
            session2 = requests.Session()
            user_agent = self.session.headers['User-Agent']
            session1.headers.update({'User-Agent': user_agent})
            session2.headers.update({'User-Agent': user_agent})

            response1 = session1.get(url, timeout=self.timeout)
            response2 = session2.get(url, timeout=self.timeout)

            session_cookies1 = [c for c in session1.cookies if any(term in c.name.lower() for term in ['session', 'auth', 'token', 'id', 'wordpress', 'woocommerce'])]
            session_cookies2 = [c for c in session2.cookies if any(term in c.name.lower() for term in ['session', 'auth', 'token', 'id', 'wordpress', 'woocommerce'])]

            if not session_cookies1 or not session_cookies2:
                self.log("No session cookies found to test.", "warning")
                return issues

            for cookie1 in session_cookies1:
                for cookie2 in session_cookies2:
                    if cookie1.name == cookie2.name:
                        if cookie1.value == cookie2.value and not self.safe_mode:
                            issues.append({
                                'issue': 'Identical session identifiers',
                                'description': f'Cookie {cookie1.name} has the same value across sessions, indicating poor session management in WordPress.',
                                'severity': 'Critical',
                                'cookie_name': cookie1.name
                            })
                            self.log(f"Critical issue: {cookie1.name} cookie has identical values!", "vuln")
                        elif len(cookie1.value) < 16:
                            issues.append({
                                'issue': 'Short session identifier',
                                'description': f'Cookie {cookie1.name} is only {len(cookie1.value)} characters, vulnerable to brute force.',
                                'severity': 'Medium',
                                'cookie_name': cookie1.name
                            })
                            self.log(f"Medium severity issue: {cookie1.name} cookie value too short!", "vuln")

        except requests.RequestException as e:
            self.log(f"Error testing session management: {e}", "error")

        return issues

    def test_cookie_theft(self, url):
        """Test for cookie theft vulnerabilities."""
        self.log(f"Testing for cookie theft vulnerabilities at {url}...")
        issues = []

        try:
            response = self.session.get(url, timeout=self.timeout)
            if not self.session.cookies:
                self.log("No cookies found to test.", "warning")
                return issues

            sensitive_cookies = [c for c in self.session.cookies if any(term in c.name.lower() for term in ['session', 'auth', 'token', 'id', 'user', 'wordpress', 'woocommerce'])]

            for cookie in sensitive_cookies:
                if not cookie.secure:
                    issues.append({
                        'issue': 'Sensitive cookie transmitted over HTTP',
                        'description': f'Cookie {cookie.name} can be intercepted over HTTP, risking WordPress session theft.',
                        'severity': 'High',
                        'cookie_name': cookie.name
                    })
                    self.log(f"High severity issue: {cookie.name} cookie over HTTP!", "vuln")
                if not cookie.has_nonstandard_attr('httponly'):
                    issues.append({
                        'issue': 'Sensitive cookie accessible via JavaScript',
                        'description': f'Cookie {cookie.name} is vulnerable to XSS theft in WordPress.',
                        'severity': 'High',
                        'cookie_name': cookie.name
                    })
                    self.log(f"High severity issue: {cookie.name} cookie accessible to JavaScript!", "vuln")

        except requests.RequestException as e:
            self.log(f"Error testing for cookie theft: {e}", "error")

        return issues

    def run(self):
        """Run all cookie security tests."""
        self.log(f"Starting cookie security tests for {self.target_url}...")

        # Attempt WordPress login if credentials provided
        login_url = urljoin(self.target_url, '/wp-login.php')
        if self.wp_username and self.wp_password:
            self.wordpress_login(login_url)
            time.sleep(1)  # Rate-limiting to avoid security plugin triggers

        # Crawl WordPress endpoints
        urls_to_test = self.crawl_wordpress_endpoints()
        self.log(f"Testing {len(urls_to_test)} WordPress endpoints...")

        # Run tests for each URL
        for url in urls_to_test:
            cookie_security_issues = self.test_cookie_security(url)
            session_management_issues = self.test_session_management(url)
            cookie_theft_issues = self.test_cookie_theft(url)
            
            self.results.append({
                'url': url,
                'cookie_security_issues': cookie_security_issues,
                'session_management_issues': session_management_issues,
                'cookie_theft_issues': cookie_theft_issues
            })
            time.sleep(0.5)  # Rate-limiting

        # Generate summary
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for result in self.results:
            for issue_list in [result['cookie_security_issues'], result['session_management_issues'], result['cookie_theft_issues']]:
                for issue in issue_list:
                    if 'issues' in issue:
                        for sub_issue in issue['issues']:
                            severity_counts[sub_issue['severity']] += 1
                    else:
                        severity_counts[issue['severity']] += 1

        total_issues = sum(severity_counts.values())
        self.log(f"Cookie security testing completed. Found {total_issues} issues:", "info")
        self.log(f"Critical: {severity_counts['Critical']}", "error" if severity_counts['Critical'] > 0 else "info")
        self.log(f"High: {severity_counts['High']}", "error" if severity_counts['High'] > 0 else "info")
        self.log(f"Medium: {severity_counts['Medium']}", "warning" if severity_counts['Medium'] > 0 else "info")
        self.log(f"Low: {severity_counts['Low']}", "info")

        # Save results to JSON
        results_file = f"{self.output_dir}/cookie_security_results.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.log(f"Results saved to {results_file}", "success")

        # Generate WordPress-specific report
        report_file = f"{self.output_dir}/cookie_security_report.md"
        with open(report_file, 'w') as f:
            f.write(f"# Cookie Security Vulnerability Report for WordPress\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"## Summary\n\n")
            f.write(f"- Total issues found: {total_issues}\n")
            f.write(f"- Critical: {severity_counts['Critical']}\n")
            f.write(f"- High: {severity_counts['High']}\n")
            f.write(f"- Medium: {severity_counts['Medium']}\n")
            f.write(f"- Low: {severity_counts['Low']}\n\n")

            for result in self.results:
                url = result['url']
                f.write(f"## Results for {url}\n\n")
                
                if result['cookie_security_issues']:
                    f.write(f"### Cookie Security Issues\n\n")
                    for issue in result['cookie_security_issues']:
                        f.write(f"#### Cookie: {issue['cookie_name']}\n\n")
                        f.write(f"- **Domain**: {issue['cookie_domain'] or 'Not specified'}\n")
                        f.write(f"- **Path**: {issue['cookie_path'] or '/'}\n\n")
                        for sub_issue in issue['issues']:
                            f.write(f"##### {sub_issue['issue']} ({sub_issue['severity']})\n\n")
                            f.write(f"{sub_issue['description']}\n\n")
                else:
                    f.write("No cookie security issues found.\n\n")

                if result['session_management_issues']:
                    f.write(f"### Session Management Issues\n\n")
                    for i, issue in enumerate(result['session_management_issues']):
                        f.write(f"#### Issue #{i+1}: {issue['issue']} ({issue['severity']})\n\n")
                        f.write(f"- **Cookie**: {issue['cookie_name']}\n")
                        f.write(f"- **Description**: {issue['description']}\n\n")
                else:
                    f.write("No session management issues found.\n\n")

                if result['cookie_theft_issues']:
                    f.write(f"### Cookie Theft Vulnerabilities\n\n")
                    for i, issue in enumerate(result['cookie_theft_issues']):
                        f.write(f"#### Issue #{i+1}: {issue['issue']} ({issue['severity']})\n\n")
                        f.write(f"- **Cookie**: {issue['cookie_name']}\n")
                        f.write(f"- **Description**: {issue['description']}\n\n")
                else:
                    f.write("No cookie theft vulnerabilities found.\n\n")

            f.write(f"## WordPress-Specific Recommendations\n\n")
            f.write("1. **Force HTTPS**: Ensure your WordPress site uses HTTPS. Add to `wp-config.php`:\n")
            f.write("    ```php\n    define('FORCE_SSL_LOGIN', true);\n    define('FORCE_SSL_ADMIN', true);\n    ```\n")
            f.write("2. **Secure Cookies**: Set secure cookie flags in `wp-config.php`:\n")
            f.write("    ```php\n    define('COOKIE_DOMAIN', false);\n    @ini_set('session.cookie_httponly', true);\n    @ini_set('session.cookie_secure', true);\n    @ini_set('session.cookie_samesite', 'Lax');\n    ```\n")
            f.write("3. **Use Security Plugins**: Install Wordfence or iThemes Security to monitor and protect cookies.\n")
            f.write("4. **Short Session Expiry**: Configure WordPress to expire sessions quickly (e.g., via Auth Cookie Expiration plugin).\n")
            f.write("5. **WooCommerce Cookies**: If using WooCommerce, ensure cart and session cookies are secure. Check `wp_options` for `woocommerce_cart_hash` settings.\n")
            f.write("6. **Monitor Logs**: Check WordPress logs for unauthorized access attempts (`wp-content/debug.log` if enabled).\n")

        self.log(f"Report saved to {report_file}", "success")
        return self.results

def main():
    """Main function to run the cookie security tester."""
    parser = argparse.ArgumentParser(description="Cookie Security Tester (WordPress Enhanced)")
    parser.add_argument("url", help="Target WordPress URL to test")
    parser.add_argument("-o", "--output", default="cookie_tests", help="Output directory for test results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--wp-username", help="WordPress username for authentication")
    parser.add_argument("--wp-password", help="WordPress password for authentication")
    parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode to avoid aggressive tests")
    args = parser.parse_args()

    print(f"{Fore.CYAN}Cookie Security Tester (WordPress Enhanced){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test.{Style.RESET_ALL}\n")

    tester = CookieSecurityTester(
        args.url, args.output, args.verbose, args.timeout,
        args.wp_username, args.wp_password, args.safe_mode
    )
    tester.run()

if __name__ == "__main__":
    main()
