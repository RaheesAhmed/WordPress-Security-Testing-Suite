# WordPress Security Testing Suite

Welcome to the **WordPress Security Testing Suite**, a robust collection of Python scripts designed to identify, exploit, and analyze vulnerabilities in WordPress websites. This suite empowers website owners and security professionals to test for critical vulnerabilities such as **SQL Injection**, **Cross-Site Scripting (XSS)**, **Cross-Site Request Forgery (CSRF)**, **cookie security issues**, and more, ensuring your site (e.g., `https://example.com`) is protected against real-world attacks. Additionally, it includes a unique scanner that leverages Anthropic's Claude model to generate detailed vulnerability reports.

> **⚠️ Legal and Ethical Warning**
> Use this suite **only on websites you own or have explicit permission to test**. Unauthorized testing is illegal and unethical. Exploitation mode (`--exploit`) may trigger security plugins (e.g., Wordfence), affect live users, or violate hosting terms. Always test in a staging environment and back up your site before running tests.

---

## Table of Contents

1.  [Features](#features)
2.  [Scripts Included](#scripts-included)
3.  [Prerequisites](#prerequisites)
4.  [Installation](#installation)
5.  [Usage Instructions](#usage-instructions)
    - [Website Security Tester](#website-security-tester)
    - [Website Security Scanner (Claude)](#website-security-scanner-claude)
    - [XSS Attack Tester](#xss-attack-tester)
    - [SQL Injection Tester](#sql-injection-tester)
    - [CSRF Attack Tester](#csrf-attack-tester)
    - [Cookie Security Tester](#cookie-security-tester)
6.  [Safety Guidelines](#safety-guidelines)
7.  [Interpreting Results](#interpreting-results)
8.  [Fixing Vulnerabilities](#fixing-vulnerabilities)
9.  [Contributing](#contributing)
10. [License](#license)
11. [Contact](#contact)

---

## Features

- **Comprehensive Testing**: Scans for SQL Injection, XSS, CSRF, cookie security issues, and missing headers.
- **Exploitation Mode**: Controlled exploitation (`--exploit`) to confirm vulnerabilities by extracting data, stealing cookies, or submitting unauthorized forms.
- **AI-Powered Scanning**: Uses Anthropic's Claude model (`website_security_scanner.py`) to generate detailed vulnerability reports.
- **WordPress-Specific**: Targets WordPress endpoints (e.g., `/wp-login.php`, `/?s=`, `/my-account/`), tables (`wp_users`, `wp_options`), and WooCommerce fields.
- **Severity Classification**: Labels vulnerabilities as **Critical**, **High**, **Medium**, or **Low** based on impact.
- **Detailed Reporting**: Generates JSON and Markdown reports with exploit results and remediation steps.
- **Safety Controls**: Uses unique test IDs, rate-limiting, and non-destructive payloads to minimize risks.

---

## Scripts Included

The suite includes six Python scripts, each tailored for specific testing needs:

1.  **`website_security_tester.py`**
    A comprehensive tester that scans for all vulnerabilities (SQLi, XSS, CSRF, cookies, etc.) with optional exploitation.

2.  **`website_security_scanner.py`**
    Scans vulnerabilities and generates detailed reports using Anthropic's Claude model, ideal for in-depth analysis.

3.  **`xss_attack_tester.py`**
    Focused on Cross-Site Scripting (XSS) vulnerabilities, with payloads for cookie theft and form manipulation.

4.  **`sql_injection_tester.py`**
    Tests for SQL Injection vulnerabilities, targeting WordPress tables like `wp_users` and `wp_options`.

5.  **`csrf_attack_tester.py`**
    Identifies CSRF vulnerabilities by checking for missing nonces and simulating unauthorized form submissions.

6.  **`cookie_security_tester.py`**
    Checks for cookie security issues, such as missing Secure, HttpOnly, or SameSite attributes.

---

## Prerequisites

Before using the suite, ensure you have the following:

- **Python 3.6+**: Installed on your system ([Download Python](https://www.python.org/downloads/)).
- **Dependencies**: Python libraries listed below.
- **WordPress Site**: A site you own or have permission to test (e.g., `https://example.com`).
- **Anthropic API Key** (for `website_security_scanner.py`): Obtain from [Anthropic](https://www.anthropic.com/).
- **Staging Environment** (recommended): A local or cloned site (e.g., using [LocalWP](https://localwp.com/)).
- **Backup Plugin**: UpdraftPlus or similar for site backups.
- **Private Browser**: For XSS tests to avoid affecting real cookies.

### Required Python Libraries

- `requests`: For HTTP requests.
- `beautifulsoup4`: For HTML parsing.
- `colorama`: For colored terminal output.
- `anthropic` (for `website_security_scanner.py`): For Claude API integration.

Install them using pip:

```bash
pip install requests beautifulsoup4 colorama anthropic
```

Alternatively, if a `requirements.txt` file is provided:

```bash
pip install -r requirements.txt
```

---

## Installation

1.  **Clone or Download the Suite:**

    - Clone the repository:
      ```bash
      git clone https://github.com/RaheesAhmed/WordPress-Security-Testing-Suite.git
      cd WordPress-Security-Testing-Suite
      ```
    - Or download the scripts and place them in a dedicated folder (e.g., `security_suite/`).

2.  **Verify Files:**
    Ensure you have the following Python scripts:

    - `website_security_tester.py`
    - `website_security_scanner.py`
    - `xss_attack_tester.py`
    - `sql_injection_tester.py`
    - `csrf_attack_tester.py`
    - `cookie_security_tester.py`

3.  **Install Dependencies:**
    Run the following command in the suite’s folder:

    ```bash
    pip install -r requirements.txt
    ```

    _(If `requirements.txt` is not provided, install libraries individually as shown in the [Prerequisites](#prerequisites) section.)_

4.  **Set Up Anthropic API Key (for `website_security_scanner.py`):**

    - Create a `.env` file in the suite’s folder:
      ```bash
      touch .env
      ```
    - Add your Anthropic API key to the `.env` file:
      ```
      ANTHROPIC_API_KEY=your-api-key-here
      ```
    - Ensure the `anthropic` library is configured to read this key (the script likely handles this if `python-dotenv` is used or similar logic is implemented).

5.  **Set Permissions (Linux/macOS):**
    Make scripts executable:
    ```bash
    chmod +x *.py
    ```

---

## Usage Instructions

Each script can be run independently, with options for verbose output, exploitation mode, and specific tests. Below are detailed instructions for each.

### Website Security Tester

- **Script:** `website_security_tester.py`
- **Purpose:** Tests all vulnerabilities (SQLi, XSS, CSRF, cookies, headers) with optional exploitation.

**Basic Usage**

Run all tests with default settings:

```bash
python website_security_tester.py https://example.com -o security_report.md
```

**With Exploitation Mode**

Test with controlled exploitation for critical vulnerabilities:

```bash
python website_security_tester.py https://example.com -o security_report.json -v --exploit
```

**Specific Test**

Test only XSS vulnerabilities:

```bash
python website_security_tester.py https://example.com -o xss_report.md -v --xss --exploit
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed output.
- `--exploit`: Attempt exploitation for critical vulnerabilities (e.g., data extraction, cookie theft).
- `--safe-mode`: Avoid generating exploitable PoCs.
- `--sql`, `--xss`, `--csrf`, `--cookies`, `--csp`, `--info`, `--headers`: Test specific vulnerabilities.
- `-t, --threads`: Number of threads (default: 5).
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[INFO] Starting security tests...
[SUCCESS] Detected WordPress site
[VULNERABILITY] Found Critical severity SQL Injection vulnerability at https://example.com/?s=test
[EXPLOIT] Exploit succeeded! Extracted data: admin@example.com
[SUCCESS] Report saved to security_report.md
```

### Website Security Scanner (Claude)

- **Script:** `website_security_scanner.py`
- **Purpose:** Scans vulnerabilities and generates detailed reports using Anthropic's Claude model.

**Basic Usage**

Run the scanner with Claude integration:

```bash
python website_security_scanner.py https://example.com -o claude_report.json --api-key $ANTHROPIC_API_KEY
```

**With Verbose Output**

Include detailed Claude analysis:

```bash
python website_security_scanner.py https://example.com -o claude_report.md -v --api-key $ANTHROPIC_API_KEY
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed Claude responses.
- `--api-key`: Anthropic API key (or set via `.env`).
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[INFO] Scanning with Claude model...
[SUCCESS] Claude detected potential XSS vulnerability in search form
[INFO] Generated detailed report with remediation steps
[SUCCESS] Report saved to claude_report.md
```

_Note: Ensure your Anthropic API key is valid and has sufficient credits. Claude’s responses may vary based on model availability._

### XSS Attack Tester

- **Script:** `xss_attack_tester.py`
- **Purpose:** Tests for XSS vulnerabilities, with payloads for cookie theft and form manipulation.

**Basic Usage**

Run XSS tests with standard payloads:

```bash
python xss_attack_tester.py https://example.com -o xss_results.json
```

**With Exploitation Mode**

Test with cookie theft attempts:

```bash
python xss_attack_tester.py https://example.com -o xss_results.md -v --exploit -l advanced
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed output.
- `--exploit`: Attempt cookie theft for critical vulnerabilities.
- `--safe-mode`: Avoid generating exploitable PoCs.
- `-l, --level`: Payload level (`basic`, `standard`, `advanced`).
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[VULNERABILITY] Potential XSS vulnerability in field s with payload: <script>alert('XSS-12345678')</script>
[EXPLOIT] Exploit succeeded! Captured cookies: {"session_id": "abc123"}
[SUCCESS] Generated XSS proof-of-concept page: xss_tests/xss_poc_1234567890.html
```

### SQL Injection Tester

- **Script:** `sql_injection_tester.py`
- **Purpose:** Tests for SQL Injection vulnerabilities, targeting WordPress tables.

**Basic Usage**

Run SQLi tests with default payloads:

```bash
python sql_injection_tester.py https://example.com -o sqli_results.json
```

**With Exploitation Mode**

Test with data extraction attempts:

```bash
python sql_injection_tester.py https://example.com -o sqli_results.md -v --exploit -l advanced
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed output.
- `--exploit`: Attempt data extraction for critical vulnerabilities.
- `--safe-mode`: Avoid generating exploitable PoCs.
- `-l, --level`: Payload level (`basic`, `standard`, `advanced`).
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[VULNERABILITY] Found Critical severity SQL Injection vulnerability at https://example.com/?s=test
[EXPLOIT] Exploit succeeded! Extracted data: admin, admin@example.com
[SUCCESS] Report saved to sqli_results.md
```

### CSRF Attack Tester

- **Script:** `csrf_attack_tester.py`
- **Purpose:** Tests for CSRF vulnerabilities by checking for missing nonces.

**Basic Usage**

Run CSRF tests:

```bash
python csrf_attack_tester.py https://example.com -o csrf_results.json
```

**With Exploitation Mode**

Test with unauthorized form submissions:

```bash
python csrf_attack_tester.py https://example.com -o csrf_results.md -v --exploit
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed output.
- `--exploit`: Attempt unauthorized form submissions.
- `--safe-mode`: Avoid generating exploitable PoCs.
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[VULNERABILITY] Found High severity CSRF vulnerability at https://example.com/my-account/
[EXPLOIT] CSRF exploit succeeded! Form submitted with data: {"email": "test-uuid@example.com"}
[SUCCESS] Generated CSRF proof-of-concept page: csrf_tests/csrf_poc_1234567890.html
```

### Cookie Security Tester

- **Script:** `cookie_security_tester.py`
- **Purpose:** Checks for cookie security issues (e.g., missing Secure, HttpOnly, SameSite attributes).

**Basic Usage**

Run cookie security tests:

```bash
python cookie_security_tester.py https://example.com -o cookie_results.json
```

**With Verbose Output**

Include detailed cookie analysis:

```bash
python cookie_security_tester.py https://example.com -o cookie_results.md -v
```

**Options**

- `-o, --output`: Output file (`.md` or `.json`).
- `-v, --verbose`: Show detailed output.
- `--timeout`: Request timeout in seconds (default: 10).

**Example Output**

```
[VULNERABILITY] Found Medium severity Cookie Security Issues at https://example.com
[INFO] Cookie 'session_id' missing HttpOnly and SameSite attributes
[SUCCESS] Report saved to cookie_results.md
```

---

## Safety Guidelines

To avoid disruptions or legal issues, follow these guidelines:

1.  **Test in Staging:**

    - Use a local or staging site (e.g., via LocalWP) to avoid affecting live users.
    - Example: Clone `https://example.com` to `http://localhost/quickvinpro`.

2.  **Backup Your Site:**

    - Install UpdraftPlus or a similar plugin and create a full backup before testing.
    - Schedule regular backups for safety.

3.  **Disable Security Plugins Temporarily:**

    - Consider disabling Wordfence or iThemes Security during tests to avoid blocks or interference.
    - Remember to re-enable them after testing.

4.  **Use a Private Browser:**

    - For XSS tests, use a private/incognito browser session to avoid affecting your real browser cookies.

5.  **Monitor Logs:**

    - Check `wp-content/debug.log` (if enabled) and hosting server logs for errors or security alerts during testing.
    - Enable debugging in `wp-config.php` if needed:
      ```php
      define('WP_DEBUG', true);
      define('WP_DEBUG_LOG', true);
      ```

6.  **Rate Limiting:**

    - The suite includes built-in rate-limiting (`time.sleep(0.5)`) to avoid overwhelming your server.
    - Adjust the `--timeout` option if needed for slower servers.

7.  **Exploitation Mode:**

    - Use `--exploit` cautiously, as it attempts real attacks (e.g., cookie theft, data extraction).
    - Ensure no real user data is affected by using dummy data with unique identifiers during tests.

8.  **Anthropic API Usage:**
    - Ensure your Anthropic API key has sufficient credits for `website_security_scanner.py`.
    - Monitor API usage to avoid unexpected costs or rate limits.

---

## Interpreting Results

Each script generates reports in the respective output directory (`security_tests/`, `xss_tests/`, `sqli_tests/`, `csrf_tests/`, `cookie_tests/`):

**JSON Reports (e.g., `security_report.json`):**

- Contain structured data with vulnerability details, severity, and exploit results.
- Example:
  ```json
  {
    "target": "https://example.com",
    "summary": {
      "total_vulnerabilities": 3,
      "critical_severity": 1,
      "successful_exploits": 1
    },
    "vulnerabilities": [
      {
        "type": "SQL Injection",
        "severity": "Critical",
        "exploit_success": true,
        "exploit_captured_data": "admin, admin@example.com"
      }
    ]
  }
  ```

**Markdown Reports (e.g., `security_report.md`):**

- Provide a human-readable summary with remediation steps.
- Example:

  ```markdown
  # Security Test Results for https://example.com

  ## Summary

  - Total Vulnerabilities: 3
  - Critical Severity: 1
  - Successful Exploits: 1

  ## Vulnerabilities

  ### SQL Injection (1)

  **Critical Severity**: https://example.com/?s=test

  - Details: SQL error with payload: ' UNION SELECT user_login,user_email FROM wp_users --
  - Exploit Success: Yes
  - Captured Data: admin, admin@example.com
  ```

**Claude Reports (e.g., `claude_report.md`):**

- Include AI-generated analysis and remediation steps.
- Example:

  ```markdown
  # Claude Security Scan for https://example.com

  ## Findings

  - XSS vulnerability in search form: Unescaped 's' parameter.

  ## Recommendations

  - Use esc_html() for output sanitization.
  ```

**Proof-of-Concept (PoC) Pages:**

- XSS and CSRF testers generate HTML PoCs (e.g., `xss_poc_1234567890.html`) for manual verification.
- Open these files in a private browser and interact with them (e.g., click buttons) to confirm the vulnerabilities (e.g., trigger JavaScript alerts).

**Severity Levels**

- **Critical:** Exploitable vulnerabilities leading to significant impact (e.g., data extraction, remote code execution, full account takeover).
- **High:** Vulnerabilities that can often be exploited but might require some user interaction or specific conditions (e.g., stored XSS, CSRF on critical actions).
- **Medium:** Configuration issues or vulnerabilities with less direct impact (e.g., missing HttpOnly flag on session cookies, weak CSP).
- **Low / Informational:** Issues that provide information to attackers or represent minor security weaknesses (e.g., server header disclosure, missing minor security headers).

---

## Fixing Vulnerabilities

If vulnerabilities are found, apply these WordPress-specific fixes:

**SQL Injection**

- **Use Prepared Statements:** Always use `$wpdb->prepare` for database queries.
  ```php
  $wpdb->prepare("SELECT * FROM wp_users WHERE ID = %d", $id);
  ```
- **Sanitize Inputs:** Use appropriate sanitization functions like `sanitize_text_field()`, `absint()`, etc.
  ```php
  $input = sanitize_text_field($_POST['input']);
  ```

**Cross-Site Scripting (XSS)**

- **Escape Outputs:** Use functions like `esc_html()`, `esc_attr()`, `esc_js()`, `esc_url()`.
  ```php
  echo esc_html($_GET['s']);
  ```
- **Add Content Security Policy (CSP):** Define a strict CSP via headers (e.g., in `functions.php` or using a plugin).
  ```php
  add_action('wp_headers', function($headers) {
      $headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';";
      return $headers;
  });
  ```

**Cross-Site Request Forgery (CSRF)**

- **Add Nonces to Forms:** Use `wp_nonce_field()` within your forms.
  ```php
  wp_nonce_field('my_action', 'my_nonce');
  ```
- **Verify Nonces:** Check the nonce on the server-side using `wp_verify_nonce()`.
  ```php
  if (!isset($_POST['my_nonce']) || !wp_verify_nonce($_POST['my_nonce'], 'my_action')) {
      wp_die('Invalid nonce');
  }
  ```

**Cookie Security**

- **Set Secure, HttpOnly, and SameSite:** Configure these attributes for sensitive cookies.
  - In PHP: `setcookie('name', 'value', ['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);`
  - In `wp-config.php` (for session cookies):
    ```php
    @ini_set('session.cookie_httponly', true);
    @ini_set('session.cookie_secure', true);
    @ini_set('session.use_only_cookies', true);
    // Consider SameSite via .htaccess or server config if needed
    ```

**Information Disclosure**

- **Remove Server Headers:** Use `.htaccess` or server configuration to unset headers like `Server` and `X-Powered-By`.
  ```htaccess
  Header unset Server
  Header unset X-Powered-By
  ```

**Security Headers**

- **Add Recommended Headers:** Implement headers like `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Strict-Transport-Security` (HSTS) via `functions.php` or `.htaccess`.
  ```php
  add_action('wp_headers', function($headers) {
      $headers['X-Content-Type-Options'] = 'nosniff';
      $headers['X-Frame-Options'] = 'DENY'; // Or SAMEORIGIN
      $headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
      // Add HSTS if site is fully HTTPS
      // $headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
      return $headers;
  });
  ```

**WooCommerce**

- **Sanitize Fields:** Ensure all custom fields and outputs in WooCommerce templates (`woocommerce/templates/`) are properly sanitized/escaped.
  ```php
  echo esc_html($billing_first_name);
  ```

**General Recommendations**

- **Install Security Plugins:** Use reputable plugins like Wordfence or iThemes Security for firewall, malware scanning, and login protection.
- **Update Everything:** Keep WordPress core, all plugins, and themes updated to their latest versions.
- **Harden Configuration:** Apply security hardening measures, such as disabling file editing in `wp-config.php`:
  ```php
  define('DISALLOW_FILE_EDIT', true);
  ```

---

## Contributing

We welcome contributions to improve the suite! To contribute:

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/new-test`).
3.  Commit your changes (`git commit -m "Add new test for file uploads"`).
4.  Push to the branch (`git push origin feature/new-test`).
5.  Open a Pull Request.

Please ensure your code follows PEP 8 guidelines and includes appropriate documentation or comments.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contact

For questions, issues, or feedback, please contact:

- **Email:** [rahesahmed37@gmail.com](mailto:rahesahmed37@gmail.com)
- **GitHub Issues:** [Open an issue](https://github.com/RaheesAhmed/WordPress-Security-Testing-Suite/issues)

---

Secure your WordPress site today!Run the suite, fix vulnerabilities, and stay safe from attackers. Happy testing! 🚀
