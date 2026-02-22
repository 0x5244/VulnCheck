# main.py

import sys
from termcolor import colored
import concurrent.futures

# Import all the test modules
from tests import (
    ssl_tls,
    headers,
    xss,
    sql_injection,
    content_discovery,
    csrf,
    directory_traversal,
    idor,
    file_upload,
    unvalidated_redirects,
    security_misconfiguration,
    sensitive_data_exposure,
    authentication,
    http_methods,
    cookie_settings,
    clickjacking,
    third_party_vulnerabilities,
    firewall_circumvention,  # Import the firewall circumvention script
)

def is_valid_domain(domain):
    import re
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'       # First character of the domain
        r'(?:[a-zA-Z0-9-]{0,61}'  # Sub domain + hostname
        r'[a-zA-Z0-9])?\.)'       # Domain name
        r'+[a-zA-Z]{2,6}$'        # Top level domain
    )
    return pattern.match(domain)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <domain> [-fc]")
        sys.exit(1)
    
    domain = sys.argv[1]

    if not is_valid_domain(domain):
        print("Invalid domain format.")
        sys.exit(1)

    # Check if the firewall circumvention option is enabled
    enable_firewall_circumvention = '-fc' in sys.argv

    print(colored(f"Starting security scan on {domain}\n", "cyan"))

    # Initialize results dictionary
    results = {
        'passed': [],
        'failed': [],
        'firewall_blocked': []
    }

    # List of test functions and their names
    test_functions = [
        ('SSL/TLS Check', ssl_tls.check_ssl_certificate),
        ('HTTP Headers Check', headers.check_headers),
        ('XSS Vulnerability', xss.test_xss),
        ('SQL Injection Vulnerability', sql_injection.test_sql_injection),
        ('Content Discovery', content_discovery.content_discovery),
        ('CSRF Protection', csrf.check_csrf_protection),
        ('Directory Traversal', directory_traversal.test_directory_traversal),
        ('Insecure Direct Object References', idor.test_idor),
        ('File Upload Vulnerability', file_upload.test_file_upload),
        ('Unvalidated Redirects and Forwards', unvalidated_redirects.test_unvalidated_redirects),
        ('Security Misconfiguration', security_misconfiguration.check_security_misconfiguration),
        ('Sensitive Data Exposure', sensitive_data_exposure.check_sensitive_data_exposure),
        ('Broken Authentication and Session Management', authentication.test_authentication),
        ('HTTP Methods Allowed', http_methods.check_http_methods),
        ('Cookie Security Settings', cookie_settings.check_cookie_settings),
        ('Clickjacking Vulnerability', clickjacking.test_clickjacking),
        ('Third-Party Library Vulnerabilities', third_party_vulnerabilities.check_third_party_vulnerabilities),
    ]

    # Include firewall circumvention test if the option is enabled
    if enable_firewall_circumvention:
        print(colored("Firewall Circumvention Test enabled.\n", "yellow"))
        test_functions.append(('Firewall Circumvention Test', firewall_circumvention.test_firewall_circumvention))

    # Run tests in parallel using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_test = {executor.submit(func, domain): name for name, func in test_functions}
        for future in concurrent.futures.as_completed(future_to_test):
            name = future_to_test[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    'status': False,
                    'details': f"Test generated an exception: {exc}",
                    'remediation': "Check the test implementation and ensure the target domain is accessible."
                }

            # Categorize the results
            if "firewall" in result['details'].lower():
                results['firewall_blocked'].append((name, result))
            elif result['status']:
                results['passed'].append((name, result))
            else:
                results['failed'].append((name, result))

    # Display results
    print(colored("\nSecurity Scan Results:\n", "cyan", attrs=['bold']))

    # Display Passed Tests
    print(colored("✔ Passed Tests:\n", "green", attrs=['bold', 'underline']))
    if results['passed']:
        for test, result in results['passed']:
            print(f"{test}: {colored('✔ Passed', 'green')}")
            if result['details']:
                print(f"Details: {result['details']}\n")
    else:
        print("No tests passed.\n")

    # Display Failed Tests
    print(colored("✖ Failed Tests:\n", "red", attrs=['bold', 'underline']))
    if results['failed']:
        for test, result in results['failed']:
            print(f"{test}: {colored('✖ Failed', 'red')}")
            if result['details']:
                print(f"Details: {result['details']}")
            if result.get('remediation'):
                print(colored(f"Remediation: {result['remediation']}\n", "yellow"))
    else:
        print("No failed tests.\n")

    # Display Tests Blocked by Firewall
    print(colored("⚠ Tests Blocked by Firewall:\n", "yellow", attrs=['bold', 'underline']))
    if results['firewall_blocked']:
        for test, result in results['firewall_blocked']:
            print(f"{test}: {colored('⚠ Blocked by Firewall', 'yellow')}")
            if result['details']:
                print(f"Details: {result['details']}")
            if result.get('remediation'):
                print(colored(f"Remediation: {result['remediation']}\n", "yellow"))
    else:
        print("No tests were blocked by the firewall.\n")

if __name__ == "__main__":
    main()
