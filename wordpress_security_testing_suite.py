#!/usr/bin/env python3
"""
WordPress Security Testing Suite with Gradio UI

A comprehensive security testing tool that combines multiple security testing modules:
- General Website Security Testing
- XSS Attack Testing
- CSRF Attack Testing
- SQL Injection Testing
- Cookie Security Testing

For educational purposes only - use only on websites you own or have permission to test.
"""

import os
import sys
import time
import json
import threading
import argparse
import gradio as gr
from datetime import datetime
from pathlib import Path
import pandas as pd
import markdown
import uuid

# Import security testing modules
from website_security_tester import WebSecurityTester
from xss_attack_tester import XSSTester
from csrf_attack_tester import CSRFAttackTester
from sql_injection_tester import SQLInjectionTester
from cookie_security_tester import CookieSecurityTester

# Set up colorama for terminal output
from colorama import init, Fore, Style
init()

class WordPressSecurityTestingSuite:
    def __init__(self, output_dir="security_suite_results"):
        """
        Initialize the security testing suite.

        Args:
            output_dir: Base directory to save test results
        """
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(output_dir, f"session_{self.timestamp}")

        # Create output directories
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "cookie_tests"), exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "csrf_tests"), exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "xss_tests"), exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "sqli_tests"), exist_ok=True)
        os.makedirs(os.path.join(self.session_dir, "security_tests"), exist_ok=True)

        # Initialize results
        self.results = {
            "timestamp": self.timestamp,
            "cookie_security": None,
            "csrf": None,
            "xss": None,
            "sqli": None,
            "general_security": None
        }

        # Initialize test status
        self.test_status = {
            "cookie_security": "Not started",
            "csrf": "Not started",
            "xss": "Not started",
            "sqli": "Not started",
            "general_security": "Not started"
        }

        # Initialize summary
        self.summary = {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        # Initialize logs
        self.logs = []

    def log(self, message, level="info"):
        """Log messages with color coding and store in logs list."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level.upper()}] {message}"
        self.logs.append(log_entry)

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

        return "\n".join(self.logs[-20:])  # Return the last 20 logs for UI display

    def run_general_security_test(self, target_url, verbose=False, timeout=10, threads=5,
                                safe_mode=False, exploit=False, progress=gr.Progress()):
        """Run general website security tests."""
        self.log(f"Starting general security tests for {target_url}...")
        self.test_status["general_security"] = "Running"

        try:
            # Create output directory
            output_dir = os.path.join(self.session_dir, "security_tests")

            # Initialize tester
            tester = WebSecurityTester(
                target_url, verbose, threads, timeout, output_dir, safe_mode, exploit
            )

            # Run tests
            progress(0.1, "Crawling website...")
            tester.crawl_website()

            progress(0.2, "Testing SQL injection...")
            tester.test_sql_injection()

            progress(0.35, "Testing XSS vulnerabilities...")
            tester.test_xss()

            progress(0.5, "Testing CSRF vulnerabilities...")
            tester.test_csrf()

            progress(0.65, "Testing cookie security...")
            tester.test_cookie_security()

            progress(0.75, "Testing content security policy...")
            tester.test_content_security_policy()

            progress(0.85, "Testing information disclosure...")
            tester.test_information_disclosure()

            progress(0.95, "Testing security headers...")
            tester.test_security_headers()

            # Generate report
            progress(0.98, "Generating report...")
            report_file = os.path.join(output_dir, "security_report.md")
            report = tester.generate_report(report_file)

            # Update results
            self.results["general_security"] = report

            # Update summary
            self.summary["total_vulnerabilities"] += report["summary"]["total_vulnerabilities"]
            self.summary["critical"] += report["summary"]["critical_severity"]
            self.summary["high"] += report["summary"]["high_severity"]
            self.summary["medium"] += report["summary"]["medium_severity"]
            self.summary["low"] += report["summary"]["low_severity"]

            self.test_status["general_security"] = "Completed"
            self.log(f"General security tests completed. Found {report['summary']['total_vulnerabilities']} vulnerabilities.", "success")

            # Read the markdown report
            with open(report_file, 'r') as f:
                md_content = f.read()

            # Create a summary table
            summary_df = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Low', 'Total'],
                'Count': [
                    report['summary']['critical_severity'],
                    report['summary']['high_severity'],
                    report['summary']['medium_severity'],
                    report['summary']['low_severity'],
                    report['summary']['total_vulnerabilities']
                ]
            })

            # Create a vulnerabilities table
            if report['vulnerabilities']:
                vuln_data = []
                for vuln in report['vulnerabilities']:
                    vuln_data.append({
                        'Type': vuln['type'],
                        'URL': vuln['url'],
                        'Severity': vuln['severity'],
                        'Description': vuln['description'][:50] + '...' if len(vuln['description']) > 50 else vuln['description']
                    })
                vuln_df = pd.DataFrame(vuln_data)
            else:
                vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})

            progress(1.0, "Done!")
            return self.log("General security tests completed."), md_content, summary_df, vuln_df, report_file

        except Exception as e:
            self.test_status["general_security"] = "Failed"
            error_msg = f"Error running general security tests: {str(e)}"
            self.log(error_msg, "error")
            return self.log(error_msg), f"# Error\n\n{error_msg}", None, None, None

    def run_xss_test(self, target_url, verbose=False, timeout=10, payload_level="standard",
                    safe_mode=False, exploit=False, progress=gr.Progress()):
        """Run XSS attack tests."""
        self.log(f"Starting XSS tests for {target_url}...")
        self.test_status["xss"] = "Running"

        try:
            # Create output directory
            output_dir = os.path.join(self.session_dir, "xss_tests")

            # Initialize tester
            tester = XSSTester(
                target_url, output_dir, verbose, timeout, safe_mode, exploit
            )

            # Run tests
            progress(0.1, "Crawling website...")
            tester.crawl_website()

            progress(0.3, "Generating XSS payloads...")
            payloads = tester.generate_xss_payloads(payload_level)

            progress(0.4, "Testing forms for XSS vulnerabilities...")
            for i, form in enumerate(tester.forms):
                progress(0.4 + (0.3 * (i / max(1, len(tester.forms)))), f"Testing form {i+1}/{len(tester.forms)}")
                tester.test_form_xss(form, payloads)

            progress(0.7, "Testing URL parameters for XSS vulnerabilities...")
            for i, url in enumerate(tester.links):
                progress(0.7 + (0.2 * (i / max(1, len(tester.links)))), f"Testing URL {i+1}/{len(tester.links)}")
                tester.test_url_parameter_xss(url, payloads)

            # Generate report
            progress(0.95, "Generating report...")

            # Count vulnerabilities by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0}
            for result in tester.results:
                severity_counts[result['severity']] += 1

            # Update summary
            self.summary["total_vulnerabilities"] += len(tester.results)
            self.summary["critical"] += severity_counts['Critical']
            self.summary["high"] += severity_counts['High']
            self.summary["medium"] += severity_counts['Medium']

            # Save results
            self.results["xss"] = {
                "total_vulnerabilities": len(tester.results),
                "critical": severity_counts['Critical'],
                "high": severity_counts['High'],
                "medium": severity_counts['Medium'],
                "successful_exploits": tester.exploits_successful,
                "vulnerabilities": tester.results
            }

            # Read the markdown report
            report_file = f"{output_dir}/xss_report.md"
            if not os.path.exists(report_file):
                # Generate report if it doesn't exist
                with open(report_file, 'w') as f:
                    f.write(f"# XSS Vulnerability Report\n\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                    f.write(f"## Summary\n\n")
                    f.write(f"- Total vulnerabilities found: {len(tester.results)}\n")
                    f.write(f"- Critical: {severity_counts.get('Critical', 0)}\n")
                    f.write(f"- High: {severity_counts.get('High', 0)}\n")
                    f.write(f"- Medium: {severity_counts.get('Medium', 0)}\n")
                    if exploit:
                        f.write(f"- Successful exploits: {tester.exploits_successful}\n")
                    f.write("\n")

                    # Add vulnerability details
                    if tester.results:
                        f.write("## Vulnerabilities\n\n")
                        for i, vuln in enumerate(tester.results):
                            f.write(f"### Vulnerability #{i+1}\n\n")
                            f.write(f"- **Type**: {vuln.get('type', 'XSS')}\n")
                            f.write(f"- **URL**: {vuln.get('url', '')}\n")
                            f.write(f"- **Severity**: {vuln.get('severity', '')}\n")
                            if 'parameter' in vuln:
                                f.write(f"- **Parameter**: {vuln.get('parameter', '')}\n")
                            if 'form_action' in vuln:
                                f.write(f"- **Form Action**: {vuln.get('form_action', '')}\n")
                            if 'payload' in vuln:
                                f.write(f"- **Payload**: `{vuln.get('payload', '')}`\n")
                            if exploit and 'exploit_success' in vuln:
                                f.write(f"- **Exploit Success**: {'Yes' if vuln.get('exploit_success') else 'No'}\n")
                            f.write("\n")

            with open(report_file, 'r') as f:
                md_content = f.read()

            # Create a summary table
            summary_df = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Total'],
                'Count': [
                    severity_counts.get('Critical', 0),
                    severity_counts.get('High', 0),
                    severity_counts.get('Medium', 0),
                    len(tester.results)
                ]
            })

            # Create a vulnerabilities table
            if tester.results:
                vuln_data = []
                for vuln in tester.results:
                    vuln_data.append({
                        'Type': vuln.get('type', 'XSS'),
                        'URL': vuln.get('url', ''),
                        'Parameter/Field': vuln.get('parameter', vuln.get('field', '')),
                        'Severity': vuln.get('severity', ''),
                        'Exploit Success': 'Yes' if vuln.get('exploit_success', False) else 'No' if vuln.get('exploit_attempted', False) else '-'
                    })
                vuln_df = pd.DataFrame(vuln_data)
            else:
                vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})

            self.test_status["xss"] = "Completed"
            self.log(f"XSS tests completed. Found {len(tester.results)} vulnerabilities.", "success")

            progress(1.0, "Done!")
            return self.log("XSS tests completed."), md_content, summary_df, vuln_df, report_file

        except Exception as e:
            self.test_status["xss"] = "Failed"
            error_msg = f"Error running XSS tests: {str(e)}"
            self.log(error_msg, "error")
            return self.log(error_msg), f"# Error\n\n{error_msg}", None, None, None

    def run_csrf_test(self, target_url, verbose=False, timeout=10,
                     safe_mode=False, exploit=False, progress=gr.Progress()):
        """Run CSRF attack tests."""
        self.log(f"Starting CSRF tests for {target_url}...")
        self.test_status["csrf"] = "Running"

        try:
            # Create output directory
            output_dir = os.path.join(self.session_dir, "csrf_tests")

            # Initialize tester
            tester = CSRFAttackTester(
                target_url, output_dir, verbose, timeout, safe_mode, exploit
            )

            # Run tests
            progress(0.1, "Detecting security plugins...")
            security_plugins = tester.detect_security_plugins()

            progress(0.2, "Crawling website for forms...")
            forms = tester.crawl_site()

            progress(0.4, "Testing forms for CSRF vulnerabilities...")
            for i, form_info in enumerate(forms):
                progress(0.4 + (0.5 * (i / max(1, len(forms)))), f"Testing form {i+1}/{len(forms)}")
                tester.test_form_csrf(form_info)

            # Generate report
            progress(0.95, "Generating report...")

            # Count vulnerabilities by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Info': 0}
            for result in tester.results:
                for issue in result['issues']:
                    severity_counts[issue['severity']] += 1

            # Update summary
            total_vulns = sum(severity_counts.values()) - severity_counts['Info']
            self.summary["total_vulnerabilities"] += total_vulns
            self.summary["critical"] += severity_counts['Critical']
            self.summary["high"] += severity_counts['High']
            self.summary["medium"] += severity_counts['Medium']

            # Save results
            self.results["csrf"] = {
                "total_vulnerabilities": total_vulns,
                "critical": severity_counts['Critical'],
                "high": severity_counts['High'],
                "medium": severity_counts['Medium'],
                "successful_exploits": tester.exploits_successful,
                "forms_tested": tester.forms_tested,
                "results": tester.results
            }

            # Read the markdown report
            report_file = f"{output_dir}/csrf_report.md"
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    md_content = f.read()
            else:
                md_content = f"# CSRF Vulnerability Report\n\nNo report file generated."

            # Create a summary table
            summary_df = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Info', 'Total'],
                'Count': [
                    severity_counts['Critical'],
                    severity_counts['High'],
                    severity_counts['Medium'],
                    severity_counts['Info'],
                    total_vulns
                ]
            })

            # Create a vulnerabilities table
            if tester.results:
                vuln_data = []
                for result in tester.results:
                    url = result['url']
                    for issue in result['issues']:
                        vuln_data.append({
                            'URL': url,
                            'Form Action': issue.get('form_action', ''),
                            'Method': issue.get('method', '').upper(),
                            'Severity': issue['severity'],
                            'Issue': issue['issue'],
                            'Exploit Success': 'Yes' if issue.get('exploit_success', False) else 'No' if issue.get('exploit_attempted', False) else '-'
                        })
                vuln_df = pd.DataFrame(vuln_data)
            else:
                vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})

            self.test_status["csrf"] = "Completed"
            self.log(f"CSRF tests completed. Found {total_vulns} vulnerabilities.", "success")

            progress(1.0, "Done!")
            return self.log("CSRF tests completed."), md_content, summary_df, vuln_df, report_file

        except Exception as e:
            self.test_status["csrf"] = "Failed"
            error_msg = f"Error running CSRF tests: {str(e)}"
            self.log(error_msg, "error")
            return self.log(error_msg), f"# Error\n\n{error_msg}", None, None, None

    def run_sqli_test(self, target_url, verbose=False, timeout=10, payload_level="standard",
                     safe_mode=False, exploit=False, progress=gr.Progress()):
        """Run SQL injection attack tests."""
        self.log(f"Starting SQL injection tests for {target_url}...")
        self.test_status["sqli"] = "Running"

        try:
            # Create output directory
            output_dir = os.path.join(self.session_dir, "sqli_tests")

            # Initialize tester
            tester = SQLInjectionTester(
                target_url, output_dir, verbose, timeout, safe_mode, exploit
            )

            # Run tests
            progress(0.1, "Crawling website...")
            tester.crawl_website()

            progress(0.3, "Generating SQL injection payloads...")
            payloads = tester.generate_sql_payloads(payload_level)

            progress(0.4, "Testing forms for SQL injection vulnerabilities...")
            for i, form in enumerate(tester.forms):
                progress(0.4 + (0.3 * (i / max(1, len(tester.forms)))), f"Testing form {i+1}/{len(tester.forms)}")
                tester.test_form_sqli(form, payloads)

            progress(0.7, "Testing URL parameters for SQL injection vulnerabilities...")
            for i, url in enumerate(tester.links):
                progress(0.7 + (0.2 * (i / max(1, len(tester.links)))), f"Testing URL {i+1}/{len(tester.links)}")
                tester.test_url_parameter_sqli(url, payloads)

            # Generate report
            progress(0.95, "Generating report...")

            # Count vulnerabilities by severity
            severity_counts = {'Critical': 0, 'High': 0}
            for result in tester.results:
                severity_counts[result['severity']] += 1

            # Update summary
            self.summary["total_vulnerabilities"] += len(tester.results)
            self.summary["critical"] += severity_counts['Critical']
            self.summary["high"] += severity_counts['High']

            # Save results
            self.results["sqli"] = {
                "total_vulnerabilities": len(tester.results),
                "critical": severity_counts['Critical'],
                "high": severity_counts['High'],
                "successful_exploits": tester.exploits_successful,
                "vulnerabilities": tester.results
            }

            # Read the markdown report
            report_file = f"{output_dir}/sqli_report.md"
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    md_content = f.read()
            else:
                md_content = f"# SQL Injection Vulnerability Report\n\nNo report file generated."

            # Create a summary table
            summary_df = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Total'],
                'Count': [
                    severity_counts['Critical'],
                    severity_counts['High'],
                    len(tester.results)
                ]
            })

            # Create a vulnerabilities table
            if tester.results:
                vuln_data = []
                for vuln in tester.results:
                    vuln_data.append({
                        'Type': vuln.get('type', 'SQL Injection'),
                        'URL': vuln.get('url', ''),
                        'Parameter/Field': vuln.get('parameter', vuln.get('field', '')),
                        'Severity': vuln.get('severity', ''),
                        'Exploit Success': 'Yes' if vuln.get('exploit_success', False) else 'No' if vuln.get('exploit_attempted', False) else '-'
                    })
                vuln_df = pd.DataFrame(vuln_data)
            else:
                vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})

            self.test_status["sqli"] = "Completed"
            self.log(f"SQL injection tests completed. Found {len(tester.results)} vulnerabilities.", "success")

            progress(1.0, "Done!")
            return self.log("SQL injection tests completed."), md_content, summary_df, vuln_df, report_file

        except Exception as e:
            self.test_status["sqli"] = "Failed"
            error_msg = f"Error running SQL injection tests: {str(e)}"
            self.log(error_msg, "error")
            return self.log(error_msg), f"# Error\n\n{error_msg}", None, None, None

    def run_cookie_test(self, target_url, verbose=False, timeout=10,
                       wp_username=None, wp_password=None, safe_mode=False, progress=gr.Progress()):
        """Run cookie security tests."""
        self.log(f"Starting cookie security tests for {target_url}...")
        self.test_status["cookie_security"] = "Running"

        try:
            # Create output directory
            output_dir = os.path.join(self.session_dir, "cookie_tests")

            # Initialize tester
            tester = CookieSecurityTester(
                target_url, output_dir, verbose, timeout, wp_username, wp_password, safe_mode
            )

            # Run tests
            progress(0.1, "Crawling WordPress endpoints...")
            urls_to_test = tester.crawl_wordpress_endpoints()

            progress(0.3, "Testing cookie security...")
            for i, url in enumerate(urls_to_test):
                progress(0.3 + (0.6 * (i / max(1, len(urls_to_test)))), f"Testing URL {i+1}/{len(urls_to_test)}")
                tester.test_cookie_security(url)
                tester.test_session_management(url)
                tester.test_cookie_theft(url)

            # Generate report
            progress(0.95, "Generating report...")

            # Count issues by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for result in tester.results:
                for issue_type in ['cookie_security_issues', 'session_management_issues', 'cookie_theft_issues']:
                    for issue in result.get(issue_type, []):
                        if isinstance(issue, dict) and 'issues' in issue:
                            for sub_issue in issue['issues']:
                                severity_counts[sub_issue['severity']] += 1
                        elif isinstance(issue, dict) and 'severity' in issue:
                            severity_counts[issue['severity']] += 1

            # Update summary
            total_issues = sum(severity_counts.values())
            self.summary["total_vulnerabilities"] += total_issues
            self.summary["critical"] += severity_counts['Critical']
            self.summary["high"] += severity_counts['High']
            self.summary["medium"] += severity_counts['Medium']
            self.summary["low"] += severity_counts['Low']

            # Save results
            self.results["cookie_security"] = {
                "total_issues": total_issues,
                "critical": severity_counts['Critical'],
                "high": severity_counts['High'],
                "medium": severity_counts['Medium'],
                "low": severity_counts['Low'],
                "results": tester.results
            }

            # Read the markdown report
            report_file = f"{output_dir}/cookie_security_report.md"
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    md_content = f.read()
            else:
                md_content = f"# Cookie Security Vulnerability Report\n\nNo report file generated."

            # Create a summary table
            summary_df = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Low', 'Total'],
                'Count': [
                    severity_counts['Critical'],
                    severity_counts['High'],
                    severity_counts['Medium'],
                    severity_counts['Low'],
                    total_issues
                ]
            })

            # Create a vulnerabilities table
            if tester.results:
                vuln_data = []
                for result in tester.results:
                    url = result['url']

                    # Process cookie security issues
                    for issue in result.get('cookie_security_issues', []):
                        for sub_issue in issue.get('issues', []):
                            vuln_data.append({
                                'URL': url,
                                'Cookie': issue.get('cookie_name', ''),
                                'Type': 'Cookie Security',
                                'Issue': sub_issue.get('issue', ''),
                                'Severity': sub_issue.get('severity', '')
                            })

                    # Process session management issues
                    for issue in result.get('session_management_issues', []):
                        vuln_data.append({
                            'URL': url,
                            'Cookie': issue.get('cookie_name', ''),
                            'Type': 'Session Management',
                            'Issue': issue.get('issue', ''),
                            'Severity': issue.get('severity', '')
                        })

                    # Process cookie theft issues
                    for issue in result.get('cookie_theft_issues', []):
                        vuln_data.append({
                            'URL': url,
                            'Cookie': issue.get('cookie_name', ''),
                            'Type': 'Cookie Theft',
                            'Issue': issue.get('issue', ''),
                            'Severity': issue.get('severity', '')
                        })

                if vuln_data:
                    vuln_df = pd.DataFrame(vuln_data)
                else:
                    vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})
            else:
                vuln_df = pd.DataFrame({'Message': ['No vulnerabilities found']})

            self.test_status["cookie_security"] = "Completed"
            self.log(f"Cookie security tests completed. Found {total_issues} issues.", "success")

            progress(1.0, "Done!")
            return self.log("Cookie security tests completed."), md_content, summary_df, vuln_df, report_file

        except Exception as e:
            self.test_status["cookie_security"] = "Failed"
            error_msg = f"Error running cookie security tests: {str(e)}"
            self.log(error_msg, "error")
            return self.log(error_msg), f"# Error\n\n{error_msg}", None, None, None

    def generate_combined_report(self):
        """Generate a combined report of all test results."""
        self.log("Generating combined security report...")

        # Create report file
        report_file = os.path.join(self.session_dir, "combined_security_report.md")

        with open(report_file, 'w') as f:
            f.write(f"# WordPress Security Testing Suite - Combined Report\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Write summary
            f.write(f"## Summary\n\n")
            f.write(f"- Total vulnerabilities found: {self.summary['total_vulnerabilities']}\n")
            f.write(f"- Critical: {self.summary['critical']}\n")
            f.write(f"- High: {self.summary['high']}\n")
            f.write(f"- Medium: {self.summary['medium']}\n")
            f.write(f"- Low: {self.summary['low']}\n\n")

            # Write test status
            f.write(f"## Test Status\n\n")
            f.write("| Test | Status | Vulnerabilities |\n")
            f.write("|------|--------|----------------|\n")

            if self.results["general_security"]:
                count = self.results["general_security"]["summary"]["total_vulnerabilities"]
                f.write(f"| General Security | {self.test_status['general_security']} | {count} |\n")
            else:
                f.write(f"| General Security | {self.test_status['general_security']} | - |\n")

            if self.results["xss"]:
                count = self.results["xss"]["total_vulnerabilities"]
                f.write(f"| XSS | {self.test_status['xss']} | {count} |\n")
            else:
                f.write(f"| XSS | {self.test_status['xss']} | - |\n")

            if self.results["csrf"]:
                count = self.results["csrf"]["total_vulnerabilities"]
                f.write(f"| CSRF | {self.test_status['csrf']} | {count} |\n")
            else:
                f.write(f"| CSRF | {self.test_status['csrf']} | - |\n")

            if self.results["sqli"]:
                count = self.results["sqli"]["total_vulnerabilities"]
                f.write(f"| SQL Injection | {self.test_status['sqli']} | {count} |\n")
            else:
                f.write(f"| SQL Injection | {self.test_status['sqli']} | - |\n")

            if self.results["cookie_security"]:
                count = self.results["cookie_security"]["total_issues"]
                f.write(f"| Cookie Security | {self.test_status['cookie_security']} | {count} |\n")
            else:
                f.write(f"| Cookie Security | {self.test_status['cookie_security']} | - |\n")

            f.write("\n")

            # Write critical vulnerabilities
            f.write(f"## Critical Vulnerabilities\n\n")

            critical_found = False

            # Check general security
            if self.results["general_security"]:
                for vuln in self.results["general_security"]["vulnerabilities"]:
                    if vuln["severity"] == "Critical":
                        if not critical_found:
                            f.write("| Type | URL | Description |\n")
                            f.write("|------|-----|-------------|\n")
                            critical_found = True
                        f.write(f"| {vuln['type']} | {vuln['url']} | {vuln['description']} |\n")

            # Check XSS
            if self.results["xss"] and self.results["xss"]["vulnerabilities"]:
                for vuln in self.results["xss"]["vulnerabilities"]:
                    if vuln["severity"] == "Critical":
                        if not critical_found:
                            f.write("| Type | URL | Parameter/Field |\n")
                            f.write("|------|-----|----------------|\n")
                            critical_found = True
                        param = vuln.get('parameter', vuln.get('field', ''))
                        f.write(f"| XSS | {vuln['url']} | {param} |\n")

            # Check CSRF
            if self.results["csrf"] and self.results["csrf"]["results"]:
                for result in self.results["csrf"]["results"]:
                    for issue in result["issues"]:
                        if issue["severity"] == "Critical":
                            if not critical_found:
                                f.write("| Type | URL | Form Action |\n")
                                f.write("|------|-----|------------|\n")
                                critical_found = True
                            f.write(f"| CSRF | {result['url']} | {issue['form_action']} |\n")

            # Check SQL Injection
            if self.results["sqli"] and self.results["sqli"]["vulnerabilities"]:
                for vuln in self.results["sqli"]["vulnerabilities"]:
                    if vuln["severity"] == "Critical":
                        if not critical_found:
                            f.write("| Type | URL | Parameter/Field |\n")
                            f.write("|------|-----|----------------|\n")
                            critical_found = True
                        param = vuln.get('parameter', vuln.get('field', ''))
                        f.write(f"| SQL Injection | {vuln['url']} | {param} |\n")

            if not critical_found:
                f.write("No critical vulnerabilities found.\n")

            f.write("\n")

            # Write recommendations
            f.write(f"## Recommendations\n\n")
            f.write("Based on the security tests, here are some recommendations to improve the security of your WordPress website:\n\n")

            f.write("### General Security\n\n")
            f.write("1. **Keep WordPress Core, Themes, and Plugins Updated**\n")
            f.write("   - Regular updates include security patches for known vulnerabilities\n\n")

            f.write("### SQL Injection Prevention\n\n")
            f.write("1. **Use Prepared Statements**\n")
            f.write("   ```php\n   $stmt = $wpdb->prepare(\"SELECT * FROM table WHERE id = %d\", $id);\n   $results = $wpdb->get_results($stmt);\n   ```\n\n")

            f.write("### XSS Prevention\n\n")
            f.write("1. **Sanitize Output**\n")
            f.write("   ```php\n   echo esc_html($user_input);\n   ```\n\n")

            f.write("### CSRF Prevention\n\n")
            f.write("1. **Add WordPress Nonces to Forms**\n")
            f.write("   ```php\n   wp_nonce_field('action_name', 'field_name');\n   ```\n\n")

            f.write("### Cookie Security\n\n")
            f.write("1. **Set Secure Attributes**\n")
            f.write("   ```php\n   setcookie('name', 'value', ['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);\n   ```\n\n")

            f.write("### Additional Recommendations\n\n")
            f.write("1. **Install a Security Plugin** (e.g., Wordfence, iThemes Security)\n")
            f.write("2. **Enable Two-Factor Authentication**\n")
            f.write("3. **Implement Content Security Policy (CSP)**\n")
            f.write("4. **Regular Security Audits and Penetration Testing**\n")

        self.log(f"Combined report saved to {report_file}", "success")

        # Read the report
        with open(report_file, 'r') as f:
            md_content = f.read()

        # Create a summary table
        summary_df = pd.DataFrame({
            'Severity': ['Critical', 'High', 'Medium', 'Low', 'Total'],
            'Count': [
                self.summary['critical'],
                self.summary['high'],
                self.summary['medium'],
                self.summary['low'],
                self.summary['total_vulnerabilities']
            ]
        })

        return md_content, summary_df, report_file

# Create the Gradio UI
def create_ui():
    """Create the Gradio UI for the security testing suite."""

    # Initialize the security testing suite
    suite = WordPressSecurityTestingSuite()

    # Define CSS for modern styling
    css = """
    .gradio-container {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .tabs {
        border-radius: 10px;
        overflow: hidden;
    }
    .output-markdown {
        max-height: 500px;
        overflow-y: auto;
        padding: 15px;
        border-radius: 5px;
        background-color: #f8f9fa;
    }
    .warning {
        color: #721c24;
        background-color: #f8d7da;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    .success {
        color: #155724;
        background-color: #d4edda;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th, td {
        padding: 8px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }
    th {
        background-color: #f2f2f2;
    }
    tr:hover {
        background-color: #f5f5f5;
    }
    """

    # Define theme
    theme = gr.themes.Soft(
        primary_hue="blue",
        secondary_hue="indigo",
    ).set(
        button_primary_background_fill="*primary_500",
        button_primary_background_fill_hover="*primary_600",
        button_secondary_background_fill="*neutral_100",
        button_secondary_background_fill_hover="*neutral_200",
        input_background_fill="*neutral_50",
    )

    # Create the interface
    with gr.Blocks(css=css, theme=theme, title="WordPress Security Testing Suite") as app:
        gr.Markdown("# WordPress Security Testing Suite")
        gr.Markdown("A comprehensive security testing tool for WordPress websites. For educational purposes only - use only on websites you own or have permission to test.")

        with gr.Row():
            with gr.Column(scale=3):
                url_input = gr.Textbox(label="Target URL", placeholder="https://example.com", info="Enter the URL of the WordPress website to test")
            with gr.Column(scale=1):
                test_button = gr.Button("Run All Tests", variant="primary")

        with gr.Row():
            with gr.Column(scale=1):
                verbose = gr.Checkbox(label="Verbose Output", value=False, info="Show detailed output")
                timeout = gr.Slider(label="Timeout (seconds)", minimum=5, maximum=30, value=10, step=1, info="Request timeout in seconds")
            with gr.Column(scale=1):
                safe_mode = gr.Checkbox(label="Safe Mode", value=True, info="Avoid generating exploitable PoCs")
                exploit = gr.Checkbox(label="Exploit Mode", value=False, info="Attempt to exploit critical vulnerabilities")
            with gr.Column(scale=1):
                wp_username = gr.Textbox(label="WordPress Username (Optional)", placeholder="admin", info="For authenticated testing")
                wp_password = gr.Textbox(label="WordPress Password (Optional)", placeholder="password", type="password", info="For authenticated testing")

        with gr.Tabs() as tabs:
            with gr.TabItem("Dashboard"):
                with gr.Row():
                    logs_output = gr.Textbox(label="Logs", lines=10, max_lines=10, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        combined_report_md = gr.Markdown(label="Combined Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        combined_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    combined_report_button = gr.Button("Generate Combined Report", variant="secondary")
                    download_combined_report = gr.File(label="Download Combined Report", interactive=False)

            with gr.TabItem("General Security"):
                with gr.Row():
                    general_run_button = gr.Button("Run General Security Tests", variant="primary")

                with gr.Row():
                    general_logs = gr.Textbox(label="Logs", lines=5, max_lines=5, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        general_report_md = gr.Markdown(label="Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        general_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    general_vulns_df = gr.DataFrame(label="Vulnerabilities")

                with gr.Row():
                    download_general_report = gr.File(label="Download Report", interactive=False)

            with gr.TabItem("XSS Testing"):
                with gr.Row():
                    with gr.Column(scale=3):
                        xss_run_button = gr.Button("Run XSS Tests", variant="primary")
                    with gr.Column(scale=1):
                        xss_level = gr.Dropdown(label="Payload Level", choices=["basic", "standard", "advanced"], value="standard", info="Complexity of XSS payloads")

                with gr.Row():
                    xss_logs = gr.Textbox(label="Logs", lines=5, max_lines=5, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        xss_report_md = gr.Markdown(label="Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        xss_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    xss_vulns_df = gr.DataFrame(label="Vulnerabilities")

                with gr.Row():
                    download_xss_report = gr.File(label="Download Report", interactive=False)

            with gr.TabItem("CSRF Testing"):
                with gr.Row():
                    csrf_run_button = gr.Button("Run CSRF Tests", variant="primary")

                with gr.Row():
                    csrf_logs = gr.Textbox(label="Logs", lines=5, max_lines=5, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        csrf_report_md = gr.Markdown(label="Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        csrf_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    csrf_vulns_df = gr.DataFrame(label="Vulnerabilities")

                with gr.Row():
                    download_csrf_report = gr.File(label="Download Report", interactive=False)

            with gr.TabItem("SQL Injection Testing"):
                with gr.Row():
                    with gr.Column(scale=3):
                        sqli_run_button = gr.Button("Run SQL Injection Tests", variant="primary")
                    with gr.Column(scale=1):
                        sqli_level = gr.Dropdown(label="Payload Level", choices=["basic", "standard", "advanced"], value="standard", info="Complexity of SQL injection payloads")

                with gr.Row():
                    sqli_logs = gr.Textbox(label="Logs", lines=5, max_lines=5, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        sqli_report_md = gr.Markdown(label="Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        sqli_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    sqli_vulns_df = gr.DataFrame(label="Vulnerabilities")

                with gr.Row():
                    download_sqli_report = gr.File(label="Download Report", interactive=False)

            with gr.TabItem("Cookie Security Testing"):
                with gr.Row():
                    cookie_run_button = gr.Button("Run Cookie Security Tests", variant="primary")

                with gr.Row():
                    cookie_logs = gr.Textbox(label="Logs", lines=5, max_lines=5, autoscroll=True)

                with gr.Row():
                    with gr.Column():
                        cookie_report_md = gr.Markdown(label="Report", elem_classes=["output-markdown"])
                    with gr.Column():
                        cookie_summary_df = gr.DataFrame(label="Vulnerability Summary")

                with gr.Row():
                    cookie_vulns_df = gr.DataFrame(label="Vulnerabilities")

                with gr.Row():
                    download_cookie_report = gr.File(label="Download Report", interactive=False)

        # Define event handlers
        def run_all_tests(url, verbose, timeout, safe_mode, exploit, wp_username, wp_password):
            if not url:
                return "Please enter a target URL", None, None, None

            # Run all tests in sequence
            suite.log(f"Starting all security tests for {url}...")

            # Run general security test
            general_logs, general_md, general_summary, general_vulns, general_file = suite.run_general_security_test(
                url, verbose, timeout, 5, safe_mode, exploit
            )

            # Run XSS test
            xss_logs, xss_md, xss_summary, xss_vulns, xss_file = suite.run_xss_test(
                url, verbose, timeout, "standard", safe_mode, exploit
            )

            # Run CSRF test
            csrf_logs, csrf_md, csrf_summary, csrf_vulns, csrf_file = suite.run_csrf_test(
                url, verbose, timeout, safe_mode, exploit
            )

            # Run SQL injection test
            sqli_logs, sqli_md, sqli_summary, sqli_vulns, sqli_file = suite.run_sqli_test(
                url, verbose, timeout, "standard", safe_mode, exploit
            )

            # Run cookie security test
            cookie_logs, cookie_md, cookie_summary, cookie_vulns, cookie_file = suite.run_cookie_test(
                url, verbose, timeout, wp_username, wp_password, safe_mode
            )

            # Generate combined report
            combined_md, combined_summary, combined_file = suite.generate_combined_report()

            suite.log("All security tests completed.")

            return (
                suite.log("All tests completed."),
                combined_md, combined_summary, combined_file,
                general_logs, general_md, general_summary, general_vulns, general_file,
                xss_logs, xss_md, xss_summary, xss_vulns, xss_file,
                csrf_logs, csrf_md, csrf_summary, csrf_vulns, csrf_file,
                sqli_logs, sqli_md, sqli_summary, sqli_vulns, sqli_file,
                cookie_logs, cookie_md, cookie_summary, cookie_vulns, cookie_file
            )

        # Connect event handlers
        test_button.click(
            fn=run_all_tests,
            inputs=[url_input, verbose, timeout, safe_mode, exploit, wp_username, wp_password],
            outputs=[
                logs_output, combined_report_md, combined_summary_df, download_combined_report,
                general_logs, general_report_md, general_summary_df, general_vulns_df, download_general_report,
                xss_logs, xss_report_md, xss_summary_df, xss_vulns_df, download_xss_report,
                csrf_logs, csrf_report_md, csrf_summary_df, csrf_vulns_df, download_csrf_report,
                sqli_logs, sqli_report_md, sqli_summary_df, sqli_vulns_df, download_sqli_report,
                cookie_logs, cookie_report_md, cookie_summary_df, cookie_vulns_df, download_cookie_report
            ]
        )

        # Connect individual test buttons
        general_run_button.click(
            fn=suite.run_general_security_test,
            inputs=[url_input, verbose, timeout, gr.Number(value=5), safe_mode, exploit],
            outputs=[general_logs, general_report_md, general_summary_df, general_vulns_df, download_general_report]
        )

        xss_run_button.click(
            fn=suite.run_xss_test,
            inputs=[url_input, verbose, timeout, xss_level, safe_mode, exploit],
            outputs=[xss_logs, xss_report_md, xss_summary_df, xss_vulns_df, download_xss_report]
        )

        csrf_run_button.click(
            fn=suite.run_csrf_test,
            inputs=[url_input, verbose, timeout, safe_mode, exploit],
            outputs=[csrf_logs, csrf_report_md, csrf_summary_df, csrf_vulns_df, download_csrf_report]
        )

        sqli_run_button.click(
            fn=suite.run_sqli_test,
            inputs=[url_input, verbose, timeout, sqli_level, safe_mode, exploit],
            outputs=[sqli_logs, sqli_report_md, sqli_summary_df, sqli_vulns_df, download_sqli_report]
        )

        cookie_run_button.click(
            fn=suite.run_cookie_test,
            inputs=[url_input, verbose, timeout, wp_username, wp_password, safe_mode],
            outputs=[cookie_logs, cookie_report_md, cookie_summary_df, cookie_vulns_df, download_cookie_report]
        )

        combined_report_button.click(
            fn=suite.generate_combined_report,
            inputs=[],
            outputs=[combined_report_md, combined_summary_df, download_combined_report]
        )

    return app

# Main function
def main():
    """Main function to run the security testing suite."""
    parser = argparse.ArgumentParser(description="WordPress Security Testing Suite with Gradio UI")
    parser.add_argument("--port", type=int, default=7860, help="Port to run the Gradio server on")
    parser.add_argument("--share", action="store_true", help="Create a shareable link")
    args = parser.parse_args()

    print(f"{Fore.CYAN}WordPress Security Testing Suite{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warning: Use only on websites you own or have permission to test.{Style.RESET_ALL}\n")

    app = create_ui()
    app.launch(server_port=args.port, share=args.share)

if __name__ == "__main__":
    main()
