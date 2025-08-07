#!/usr/bin/env python3
"""
Advanced XSS Scanner with Multiple Scan Modes and Engaging Output
"""
import argparse
import requests
import time
import re
import json
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, WebDriverException, TimeoutException, JavascriptException
import threading
import queue
import sys
from colorama import init, Fore, Style
import os
import random
import string
# Initialize colorama for colored output
init()

class AdvancedXSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.reflected_vulnerabilities = []
        self.dom_vulnerabilities = []
        self.stored_vulnerabilities = []
        self.payloads = []
        self.timeout = 15
        self.driver = None
        self.results_lock = threading.Lock()
        self.verified_payloads = set()
        
        # Setup Selenium for XSS verification
        self.setup_selenium()
        
    def setup_selenium(self):
        """Setup Selenium WebDriver for XSS verification"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        chrome_options.add_argument('--disable-images')
        chrome_options.add_argument('--disable-javascript-har-promotion')
        chrome_options.add_argument('--disable-features=VizDisplayCompositor')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            self.print_success(f"{'🚀'} Selenium WebDriver setup successful!")
        except Exception as e:
            self.print_error(f"Failed to setup Selenium: {e}")
            self.print_warning("XSS verification will be limited")
            self.driver = None
    
    def restart_selenium(self):
        """Restart Selenium WebDriver if it crashes"""
        try:
            if self.driver:
                self.driver.quit()
        except:
            pass
        
        self.print_warning("Restarting Selenium WebDriver...")
        self.setup_selenium()
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Fore.MAGENTA}[ℹ️] {message}{Style.RESET_ALL}")  # Changed from dark blue to magenta
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}[✅] {message}{Style.RESET_ALL}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}[⚠️] {message}{Style.RESET_ALL}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}[❌] {message}{Style.RESET_ALL}")
    
    def print_loading(self, message, duration=2):
        """Print loading animation"""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f"\r{Fore.CYAN}[{frames[i % len(frames)]}] {message}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        
        sys.stdout.write("\r")
        sys.stdout.flush()
    
    def show_banner(self):
        """Show fancy banner"""
        banner = f"""
{Fore.RED}██████╗░██╗░░░██╗██████╗░██████╗░██╗░░░██╗██╗░░░░░███████╗  ░█████╗░░█████╗░██████╗░██████╗░░█████╗░
██╔══██╗██║░░░██║██╔══██╗██╔══██╗██║░░░██║██║░░░░░██╔════╝  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
██████╔╝██║░░░██║██████╔╝██████╔╝██║░░░██║██║░░░░░█████╗░░  ██║░░╚═╝██║░░██║██████╦╝██████╔╝███████║
██╔═══╝░██║░░░██║██╔══██╗██╔═══╝░██║░░░██║██║░░░░░██╔══╝░░  ██║░░██╗██║░░██║██╔══██╗██╔══██╗██╔══██║
██║░░░░░╚██████╔╝██║░░██║██║░░░░░╚██████╔╝███████╗███████╗  ╚█████╔╝╚█████╔╝██████╦╝██║░░██║██║░░██║
╚═╝░░░░░░╚═════╝░╚═╝░░╚═╝╚═╝░░░░░░╚═════╝░╚══════╝╚══════╝  ░╚════╝░░╚════╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝
{Fore.YELLOW}                          PHANTOM XSS Scanner v2.0{Style.RESET_ALL}
{Fore.MAGENTA}                      Scan for Reflected, DOM, and Stored XSS{Style.RESET_ALL}
"""
        print(banner)
    
    def load_payloads(self, payload_file):
        """Load XSS payloads from file"""
        if payload_file and os.path.exists(payload_file):
            try:
                with open(payload_file, 'r', encoding='utf-8') as f:
                    custom_payloads = [line.strip() for line in f if line.strip()]
                
                if custom_payloads:
                    self.payloads = custom_payloads
                    self.print_success(f"Loaded {len(custom_payloads)} payloads from {payload_file}")
                    self.print_warning("Using ONLY payloads from provided file")
                    return
            except Exception as e:
                self.print_error(f"Error loading payload file: {e}")
        
        self.print_error("No valid payloads loaded. Exiting.")
        sys.exit(1)
    
    def load_urls(self, url_file):
        """Load URLs from file"""
        urls = []
        if url_file and os.path.exists(url_file):
            try:
                with open(url_file, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                
                if urls:
                    self.print_success(f"Loaded {len(urls)} URLs from {url_file}")
                    return urls
            except Exception as e:
                self.print_error(f"Error loading URL file: {e}")
        
        self.print_error("No valid URLs loaded. Exiting.")
        sys.exit(1)
    
    def parse_query_string(self, query_string):
        """Parse query string manually to capture parameters without values"""
        params = {}
        if not query_string:
            return params
        
        # Split by '&' to get individual parameters
        param_pairs = query_string.split('&')
        
        for pair in param_pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                # URL decode the key and value
                key = urllib.parse.unquote(key)
                value = urllib.parse.unquote(value)
                
                if key not in params:
                    params[key] = []
                params[key].append(value)
            else:
                # Parameter without value (like "searchstring")
                key = urllib.parse.unquote(pair)
                if key not in params:
                    params[key] = []
                params[key].append('')
        
        return params
    
    def scan_reflected_xss(self, url, target_param=None):
        """Scan URL parameters for Reflected XSS vulnerabilities"""
        self.print_info(f"Scanning for Reflected XSS in {url}")
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Extract all parameters from URL
            if '?' in url:
                query_part = url.split('?')[1]
                self.print_info(f"Query part: {query_part}")
                
                # Use custom parser to capture parameters without values
                params = self.parse_query_string(query_part)
                self.print_info(f"Parsed parameters: {params}")
                
                if params:
                    # If target_param is specified, check if it exists
                    if target_param:
                        if target_param in params:
                            param_names = [target_param]
                            self.print_info(f"Testing only parameter: {target_param}")
                        else:
                            self.print_warning(f"Target parameter '{target_param}' not found in URL")
                            self.print_info(f"Available parameters: {list(params.keys())}")
                            self.print_info("Testing all parameters instead")
                            param_names = list(params.keys())
                    else:
                        # Test all parameters
                        param_names = list(params.keys())
                        self.print_info(f"Testing all parameters: {', '.join(param_names)}")
                    
                    # Test each parameter
                    for param_name in param_names:
                        self.print_info(f"Testing parameter: {param_name}")
                        
                        # Test each payload
                        for i, payload in enumerate(self.payloads):
                            try:
                                # Skip if we've already verified a similar payload
                                payload_key = payload.split('(')[0]
                                if payload_key in self.verified_payloads:
                                    continue
                                
                                # Create test URL with payload
                                test_params = params.copy()
                                test_params[param_name] = [payload]
                                test_query = urlencode(test_params, doseq=True)
                                test_url = f"{base_url}?{test_query}"
                                
                                # Send request
                                response = self.session.get(test_url, timeout=self.timeout)
                                
                                # Check if payload is reflected and in executable context
                                context_info = self._analyze_payload_context(response, payload)
                                if context_info['is_reflected'] and context_info['is_executable']:
                                    self.print_success(f"Potential XSS found in parameter '{param_name}'!")
                                    self.print_success(f"Payload: {payload}")
                                    self.print_info(f"Context: {context_info['context']}")
                                    
                                    # Verify the vulnerability with strict checking
                                    verified = self._verify_xss_vulnerability(test_url, param_name, payload)
                                    
                                    if verified:
                                        # Mark this payload type as verified
                                        self.verified_payloads.add(payload_key)
                                    
                                    vulnerability = {
                                        'type': 'Reflected XSS',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'verified': verified,
                                        'context': context_info['context']
                                    }
                                    
                                    with self.results_lock:
                                        self.reflected_vulnerabilities.append(vulnerability)
                                    
                                    self._report_vulnerability(vulnerability)
                                    
                            except Exception as e:
                                self.print_error(f"Error testing payload {i+1}: {e}")
                                continue
                else:
                    self.print_warning("No parameters found in URL")
            else:
                self.print_warning("No parameters found in URL")
            
        except Exception as e:
            self.print_error(f"Error scanning URL: {e}")
    
    def scan_dom_xss(self, url, target_param=None):
        """Scan URL parameters for DOM-based XSS vulnerabilities"""
        if not self.driver:
            self.print_warning("Selenium not available, skipping DOM XSS scan")
            return
        
        self.print_info(f"Scanning for DOM-based XSS in {url}")
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Extract all parameters from URL
            if '?' in url:
                query_part = url.split('?')[1]
                self.print_info(f"Query part: {query_part}")
                
                # Use custom parser to capture parameters without values
                params = self.parse_query_string(query_part)
                self.print_info(f"Parsed parameters: {params}")
                
                if params:
                    # If target_param is specified, check if it exists
                    if target_param:
                        if target_param in params:
                            param_names = [target_param]
                            self.print_info(f"Testing only parameter: {target_param}")
                        else:
                            self.print_warning(f"Target parameter '{target_param}' not found in URL")
                            self.print_info(f"Available parameters: {list(params.keys())}")
                            self.print_info("Testing all parameters instead")
                            param_names = list(params.keys())
                    else:
                        # Test all parameters
                        param_names = list(params.keys())
                        self.print_info(f"Testing all parameters: {', '.join(param_names)}")
                    
                    # Test each parameter
                    for param_name in param_names:
                        self.print_info(f"Testing parameter: {param_name}")
                        
                        # Test each payload
                        for i, payload in enumerate(self.payloads):
                            try:
                                # Skip if we've already verified a similar payload
                                payload_key = payload.split('(')[0]
                                if payload_key in self.verified_payloads:
                                    continue
                                
                                # Create test URL with payload
                                test_params = params.copy()
                                test_params[param_name] = [payload]
                                test_query = urlencode(test_params, doseq=True)
                                test_url = f"{base_url}?{test_query}"
                                
                                # Test with Selenium
                                verified = self._verify_dom_xss(test_url, param_name, payload)
                                
                                if verified:
                                    # Mark this payload type as verified
                                    self.verified_payloads.add(payload_key)
                                    
                                    vulnerability = {
                                        'type': 'DOM-based XSS',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'verified': True,
                                        'context': 'DOM-based'
                                    }
                                    
                                    with self.results_lock:
                                        self.dom_vulnerabilities.append(vulnerability)
                                    
                                    self._report_vulnerability(vulnerability)
                                    
                            except Exception as e:
                                self.print_error(f"Error testing payload {i+1}: {e}")
                                continue
                else:
                    self.print_warning("No parameters found in URL")
            else:
                self.print_warning("No parameters found in URL")
            
        except Exception as e:
            self.print_error(f"Error scanning URL: {e}")
    
    def scan_stored_xss(self, url, target_param=None):
        """Scan URL parameters for Stored XSS vulnerabilities"""
        self.print_info(f"Scanning for Stored XSS in {url}")
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Extract all parameters from URL
            if '?' in url:
                query_part = url.split('?')[1]
                self.print_info(f"Query part: {query_part}")
                
                # Use custom parser to capture parameters without values
                params = self.parse_query_string(query_part)
                self.print_info(f"Parsed parameters: {params}")
                
                if params:
                    # If target_param is specified, check if it exists
                    if target_param:
                        if target_param in params:
                            param_names = [target_param]
                            self.print_info(f"Testing only parameter: {target_param}")
                        else:
                            self.print_warning(f"Target parameter '{target_param}' not found in URL")
                            self.print_info(f"Available parameters: {list(params.keys())}")
                            self.print_info("Testing all parameters instead")
                            param_names = list(params.keys())
                    else:
                        # Test all parameters
                        param_names = list(params.keys())
                        self.print_info(f"Testing all parameters: {', '.join(param_names)}")
                    
                    # Test each parameter
                    for param_name in param_names:
                        self.print_info(f"Testing parameter: {param_name}")
                        
                        # Test each payload
                        for i, payload in enumerate(self.payloads):
                            try:
                                # Skip if we've already verified a similar payload
                                payload_key = payload.split('(')[0]
                                if payload_key in self.verified_payloads:
                                    continue
                                
                                # Create test URL with payload
                                test_params = params.copy()
                                test_params[param_name] = [payload]
                                test_query = urlencode(test_params, doseq=True)
                                test_url = f"{base_url}?{test_query}"
                                
                                # Test for stored XSS
                                verified = self._verify_stored_xss(test_url, param_name, payload)
                                
                                if verified:
                                    # Mark this payload type as verified
                                    self.verified_payloads.add(payload_key)
                                    
                                    vulnerability = {
                                        'type': 'Stored XSS',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'verified': True,
                                        'context': 'Stored'
                                    }
                                    
                                    with self.results_lock:
                                        self.stored_vulnerabilities.append(vulnerability)
                                    
                                    self._report_vulnerability(vulnerability)
                                    
                            except Exception as e:
                                self.print_error(f"Error testing payload {i+1}: {e}")
                                continue
                else:
                    self.print_warning("No parameters found in URL")
            else:
                self.print_warning("No parameters found in URL")
            
        except Exception as e:
            self.print_error(f"Error scanning URL: {e}")
    
    def _analyze_payload_context(self, response, payload):
        """Analyze the context where the payload is reflected"""
        try:
            content = response.text
            payload_lower = payload.lower()
            
            # Default context info
            context_info = {
                'is_reflected': False,
                'is_executable': False,
                'context': 'Unknown',
                'details': []
            }
            
            # Check if payload is reflected in any form
            if payload_lower not in content.lower():
                # Check for encoded payload reflection
                encoded_payloads = [
                    urllib.parse.quote(payload),
                    urllib.parse.quote_plus(payload),
                    payload.replace('<', '&lt;').replace('>', '&gt;'),
                    payload.replace('"', '&quot;').replace("'", '&#x27;')
                ]
                
                is_encoded_reflected = False
                for encoded in encoded_payloads:
                    if encoded.lower() in content.lower():
                        is_encoded_reflected = True
                        context_info['details'].append(f"Encoded as: {encoded}")
                        break
                
                if not is_encoded_reflected:
                    return context_info
            
            context_info['is_reflected'] = True
            
            # Check if payload is in HTML comment
            if f'<!--{payload_lower}' in content.lower() or f'{payload_lower}-->' in content.lower():
                context_info['context'] = 'HTML comment'
                context_info['details'].append('Payload is in HTML comment - not executable')
                return context_info
            
            # Check if payload is in textarea content
            textarea_pattern = r'<textarea[^>]*>(.*?)</textarea>'
            textarea_matches = re.findall(textarea_pattern, content, re.DOTALL | re.IGNORECASE)
            for match in textarea_matches:
                if payload_lower in match.lower():
                    context_info['context'] = 'Textarea content'
                    context_info['details'].append('Payload is in textarea content - not executable')
                    return context_info
            
            # Check if payload is in script tag but not as executable code
            script_pattern = r'<script[^>]*>(.*?)</script>'
            script_matches = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
            for match in script_matches:
                if payload_lower in match.lower():
                    # Check if it's in a string literal within the script
                    if re.search(r'["\'][^"\']*' + re.escape(payload_lower) + r'[^"\']*["\']', match, re.IGNORECASE):
                        context_info['context'] = 'Script string literal'
                        context_info['details'].append('Payload is in a string literal within script - not directly executable')
                        return context_info
            
            # Check if payload is in input value attribute
            input_value_pattern = r'<input[^>]*value\s*=\s*["\']([^"\']*)["\'][^>]*>'
            input_matches = re.finditer(input_value_pattern, content, re.IGNORECASE)
            
            for match in input_matches:
                input_value = match.group(1)
                if payload_lower in input_value.lower():
                    # Check if the payload breaks out of the value attribute
                    if '"' in payload_lower or "'" in payload_lower:
                        # Look for patterns that indicate breaking out
                        if re.search(r'["\'][^"\']*["\'][^>]*on\w+\s*=', content[match.start():match.start()+200], re.IGNORECASE):
                            context_info['context'] = 'Input value with event handler'
                            context_info['is_executable'] = True
                            context_info['details'].append('Payload breaks out of input value and creates event handler')
                            return context_info
                        elif re.search(r'["\'][^"\']*["\'][^>]*>', content[match.start():match.start()+200], re.IGNORECASE):
                            # Check if it creates HTML elements after breaking out
                            if '<' in payload_lower and '>' in payload_lower:
                                if any(tag in payload_lower for tag in ['<script', '<img', '<svg', '<iframe']):
                                    context_info['context'] = 'Input value with HTML injection'
                                    context_info['is_executable'] = True
                                    context_info['details'].append('Payload breaks out of input value and injects HTML')
                                    return context_info
                    
                    context_info['context'] = 'Input value attribute'
                    context_info['details'].append('Payload is in input value attribute - not executable')
                    return context_info
            
            # Check if payload is directly in HTML context (not in attribute)
            html_context_pattern = r'>\s*([^<]*' + re.escape(payload_lower) + r'[^<]*)\s*<'
            if re.search(html_context_pattern, content, re.IGNORECASE):
                context_info['context'] = 'HTML content'
                context_info['details'].append('Payload is in HTML content')
                
                # Check if it contains executable code
                if any(tag in payload_lower for tag in ['<script', '<img', '<svg', '<iframe', '<body']):
                    context_info['is_executable'] = True
                    context_info['details'].append('Payload contains executable HTML tags')
                
                return context_info
            
            # Check if payload is in other attributes
            attr_pattern = r'(\w+)\s*=\s*["\']([^"\']*' + re.escape(payload_lower) + r'[^"\']*)["\']'
            attr_matches = re.finditer(attr_pattern, content, re.IGNORECASE)
            
            for match in attr_matches:
                attr_name = match.group(1).lower()
                attr_value = match.group(2)
                
                # Check if it's an event handler attribute
                if attr_name.startswith('on'):
                    context_info['context'] = f'Event handler ({attr_name})'
                    context_info['is_executable'] = True
                    context_info['details'].append('Payload is in event handler attribute')
                    return context_info
                
                # Check if it breaks out of the attribute
                if '"' in payload_lower or "'" in payload_lower:
                    context_info['context'] = f'Attribute ({attr_name}) with break-out'
                    context_info['is_executable'] = True
                    context_info['details'].append('Payload breaks out of attribute')
                    return context_info
                
                context_info['context'] = f'Attribute ({attr_name})'
                context_info['details'].append('Payload is in attribute value - not executable')
                return context_info
            
            # Default case - reflected but context unclear
            context_info['context'] = 'Unknown context'
            context_info['details'].append('Payload is reflected but context is unclear')
            
            return context_info
            
        except Exception as e:
            self.print_error(f"Error analyzing payload context: {e}")
            return {
                'is_reflected': False,
                'is_executable': False,
                'context': 'Error',
                'details': [f'Error: {str(e)}']
            }
    
    def _verify_xss_vulnerability(self, url, param_name, payload):
        """Verify XSS vulnerability by checking for actual JavaScript execution"""
        self.print_info("Verifying XSS vulnerability...")
        
        if not self.driver:
            self.print_warning("Selenium not available, cannot verify")
            return False
        
        try:
            # Create a unique verification payload that will show a popup with "1"
            verification_payload = payload.replace('alert(1)', 'alert("XSS_VERIFIED_1")')
            if verification_payload == payload:
                verification_payload = payload.replace('alert("1")', 'alert("XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('confirm(1)', 'confirm("XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('prompt(1)', 'prompt("XSS_VERIFIED_1")')
            
            # If still no replacement, just use the original payload
            if verification_payload == payload:
                verification_payload = payload
            
            # Parse URL and replace parameter with verification payload
            parsed_url = urlparse(url)
            params = self.parse_query_string(parsed_url.query)
            params[param_name] = [verification_payload]
            verification_query = urlencode(params, doseq=True)
            verification_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{verification_query}"
            
            self.print_info(f"Testing verification URL: {verification_url[:100]}...")
            
            # Navigate to the URL with error handling
            try:
                self.driver.get(verification_url)
                time.sleep(3)
            except UnexpectedAlertPresentException:
                # Alert is already present - handle it
                try:
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    self.print_success(f"VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                    return True
                except:
                    pass
            except WebDriverException as e:
                self.print_error(f"WebDriver error: {e}")
                self.restart_selenium()
                return False
            
            # Check for alert with explicit wait
            try:
                alert = WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                
                self.print_success(f"VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                return True
            except TimeoutException:
                # No alert appeared - try to trigger events for onmouseover payloads
                try:
                    # For onmouseover payloads, try to trigger the event
                    if 'onmouseover' in verification_payload.lower():
                        self.print_info("Trying to trigger onmouseover event...")
                        
                        # Find all elements and try to mouse over them
                        elements = self.driver.find_elements(By.XPATH, "//*")
                        for element in elements:
                            try:
                                # Move to element
                                self.driver.execute_script("arguments[0].scrollIntoView();", element)
                                time.sleep(0.1)
                                
                                # Try to trigger mouseover
                                self.driver.execute_script("var event = new MouseEvent('mouseover', {bubbles: true, cancelable: true}); arguments[0].dispatchEvent(event);", element)
                                time.sleep(0.5)
                                
                                # Check if alert appeared
                                try:
                                    alert = self.driver.switch_to.alert
                                    alert_text = alert.text
                                    alert.accept()
                                    self.print_success(f"VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                                    return True
                                except:
                                    pass
                            except:
                                pass
                
                except Exception as e:
                    self.print_error(f"Error triggering events: {e}")
                
                # Check if payload is just in input field
                try:
                    page_source = self.driver.page_source
                    
                    # Check if payload is in input value attribute
                    input_value_pattern = r'<input[^>]*value\s*=\s*["\'][^"\']*XSS_VERIFIED_1[^"\']*["\'][^>]*>'
                    if re.search(input_value_pattern, page_source, re.IGNORECASE):
                        self.print_info("Payload found in input value attribute - checking if it breaks out...")
                        
                        # Check if the payload breaks out and creates executable code
                        break_out_pattern = r'<input[^>]*value\s*=\s*["\'][^"\']*["\'][^>]*XSS_VERIFIED_1[^"\']*["\'][^>]*on\w+\s*='
                        if re.search(break_out_pattern, page_source, re.IGNORECASE):
                            self.print_success("Payload breaks out of input value and creates event handler!")
                            return True
                        else:
                            self.print_warning("Payload is contained within input value - false positive")
                            return False
                    
                    # Check if payload is in textarea content
                    textarea_pattern = r'<textarea[^>]*>.*XSS_VERIFIED_1.*</textarea>'
                    if re.search(textarea_pattern, page_source, re.IGNORECASE | re.DOTALL):
                        self.print_warning("Payload found in textarea content - false positive")
                        return False
                    
                    # Check for other non-executable contexts
                    if 'XSS_VERIFIED_1' in page_source:
                        self.print_warning("Verification marker found in page but no alert triggered - likely false positive")
                        return False
                    
                except Exception as e:
                    self.print_error(f"Error checking page source: {e}")
            
            self.print_warning("Verification failed - no alert triggered")
            return False
            
        except Exception as e:
            self.print_error(f"Error verifying XSS: {e}")
            return False
    
    def _verify_dom_xss(self, url, param_name, payload):
        """Verify DOM-based XSS vulnerability"""
        self.print_info("Verifying DOM-based XSS vulnerability...")
        
        if not self.driver:
            self.print_warning("Selenium not available, cannot verify")
            return False
        
        try:
            # Create a unique verification payload that will show a popup with "1"
            verification_payload = payload.replace('alert(1)', 'alert("DOM_XSS_VERIFIED_1")')
            if verification_payload == payload:
                verification_payload = payload.replace('alert("1")', 'alert("DOM_XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('confirm(1)', 'confirm("DOM_XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('prompt(1)', 'prompt("DOM_XSS_VERIFIED_1")')
            
            # If still no replacement, just use the original payload
            if verification_payload == payload:
                verification_payload = payload
            
            # Parse URL and replace parameter with verification payload
            parsed_url = urlparse(url)
            params = self.parse_query_string(parsed_url.query)
            params[param_name] = [verification_payload]
            verification_query = urlencode(params, doseq=True)
            verification_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{verification_query}"
            
            self.print_info(f"Testing DOM verification URL: {verification_url[:100]}...")
            
            # Navigate to the URL
            try:
                self.driver.get(verification_url)
                time.sleep(3)
                
                # Try to find and interact with elements that might trigger DOM XSS
                # Look for elements that might have the payload in their attributes
                elements = self.driver.find_elements(By.XPATH, "//*[@*[contains(., 'DOM_XSS_VERIFIED_1')]]")
                
                for element in elements:
                    try:
                        # Try to click the element
                        element.click()
                        time.sleep(1)
                        
                        # Check if alert appeared
                        try:
                            alert = self.driver.switch_to.alert
                            alert_text = alert.text
                            alert.accept()
                            self.print_success(f"DOM XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                            return True
                        except:
                            pass
                    except:
                        pass
                
                # Try to trigger events that might execute the payload
                try:
                    # Try to trigger mouse events
                    self.driver.execute_script("""
                        var allElements = document.getElementsByTagName('*');
                        for (var i = 0; i < allElements.length; i++) {
                            var element = allElements[i];
                            
                            // Trigger mouseover event
                            var mouseoverEvent = new MouseEvent('mouseover', {
                                bubbles: true,
                                cancelable: true
                            });
                            element.dispatchEvent(mouseoverEvent);
                            
                            // Trigger click event
                            var clickEvent = new MouseEvent('click', {
                                bubbles: true,
                                cancelable: true
                            });
                            element.dispatchEvent(clickEvent);
                        }
                    """)
                    time.sleep(2)
                    
                    # Check if alert appeared
                    try:
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        self.print_success(f"DOM XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                        return True
                    except:
                        pass
                except Exception as e:
                    self.print_error(f"Error triggering DOM events: {e}")
                
                # Check for alert with explicit wait
                try:
                    alert = WebDriverWait(self.driver, 1).until(EC.alert_is_present())
                    alert_text = alert.text
                    alert.accept()
                    
                    self.print_success(f"DOM XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                    return True
                except TimeoutException:
                    pass
                
                self.print_warning("DOM XSS verification failed - no alert triggered")
                return False
                
            except WebDriverException as e:
                self.print_error(f"WebDriver error: {e}")
                self.restart_selenium()
                return False
            
        except Exception as e:
            self.print_error(f"Error verifying DOM XSS: {e}")
            return False
    
    def _verify_stored_xss(self, url, param_name, payload):
        """Verify Stored XSS vulnerability"""
        self.print_info("Verifying Stored XSS vulnerability...")
        
        if not self.driver:
            self.print_warning("Selenium not available, cannot verify")
            return False
        
        try:
            # Create a unique verification payload that will show a popup with "1"
            verification_payload = payload.replace('alert(1)', 'alert("STORED_XSS_VERIFIED_1")')
            if verification_payload == payload:
                verification_payload = payload.replace('alert("1")', 'alert("STORED_XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('confirm(1)', 'confirm("STORED_XSS_VERIFIED_1")')
            
            if verification_payload == payload:
                verification_payload = payload.replace('prompt(1)', 'prompt("STORED_XSS_VERIFIED_1")')
            
            # If still no replacement, just use the original payload
            if verification_payload == payload:
                verification_payload = payload
            
            # Parse URL and replace parameter with verification payload
            parsed_url = urlparse(url)
            params = self.parse_query_string(parsed_url.query)
            params[param_name] = [verification_payload]
            verification_query = urlencode(params, doseq=True)
            verification_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{verification_query}"
            
            self.print_info(f"Testing Stored XSS verification URL: {verification_url[:100]}...")
            
            # Navigate to the URL
            try:
                self.driver.get(verification_url)
                time.sleep(3)
                
                # Look for forms that might be used for stored XSS
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                
                for form in forms:
                    try:
                        # Find input fields in the form
                        inputs = form.find_elements(By.TAG_NAME, "input")
                        textareas = form.find_elements(By.TAG_NAME, "textarea")
                        
                        # Fill in the form with the verification payload
                        for input_field in inputs:
                            input_type = input_field.get_attribute("type")
                            if input_type in ["text", "search", "hidden", "email", "url"]:
                                try:
                                    input_field.clear()
                                    input_field.send_keys(verification_payload)
                                except:
                                    pass
                        
                        for textarea in textareas:
                            try:
                                textarea.clear()
                                textarea.send_keys(verification_payload)
                            except:
                                pass
                        
                        # Find and click the submit button
                        submit_buttons = form.find_elements(By.XPATH, ".//input[@type='submit' or @type='button'] | .//button[@type='submit' or @type='button']")
                        
                        for button in submit_buttons:
                            try:
                                button.click()
                                time.sleep(3)
                                
                                # Check if alert appeared
                                try:
                                    alert = self.driver.switch_to.alert
                                    alert_text = alert.text
                                    alert.accept()
                                    self.print_success(f"STORED XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                                    return True
                                except:
                                    pass
                            except:
                                pass
                        
                        # Try to submit via JavaScript
                        try:
                            self.driver.execute_script("arguments[0].submit();", form)
                            time.sleep(3)
                            
                            # Check if alert appeared
                            try:
                                alert = self.driver.switch_to.alert
                                alert_text = alert.text
                                alert.accept()
                                self.print_success(f"STORED XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                                return True
                            except:
                                pass
                        except:
                            pass
                    except:
                        pass
                
                # Check if the payload is stored by navigating to the page again
                try:
                    self.driver.get(verification_url)
                    time.sleep(3)
                    
                    # Check if alert appeared
                    try:
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        self.print_success(f"STORED XSS VERIFICATION SUCCESSFUL! Alert with text: {alert_text}")
                        return True
                    except:
                        pass
                except:
                    pass
                
                self.print_warning("Stored XSS verification failed - no alert triggered")
                return False
                
            except WebDriverException as e:
                self.print_error(f"WebDriver error: {e}")
                self.restart_selenium()
                return False
            
        except Exception as e:
            self.print_error(f"Error verifying Stored XSS: {e}")
            return False
    
    def _report_vulnerability(self, vulnerability):
        """Report found vulnerability"""
        print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] XSS VULNERABILITY DETECTED!{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Type: {vulnerability['type']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}URL: {vulnerability['url']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Parameter: {vulnerability['parameter']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Payload: {vulnerability['payload']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Context: {vulnerability.get('context', 'Unknown')}{Style.RESET_ALL}")
        
        if vulnerability.get('verified'):
            print(f"{Fore.GREEN}✓ VERIFIED: XSS vulnerability confirmed!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}✓ This payload causes XSS and shows popup with verification text{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}? POTENTIAL: Payload reflected but not verified as executable{Style.RESET_ALL}")
        
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
    
    def generate_report(self):
        """Generate comprehensive scan report"""
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] XSS SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # Count verified vulnerabilities only
        verified_reflected = sum(1 for v in self.reflected_vulnerabilities if v.get('verified'))
        verified_dom = sum(1 for v in self.dom_vulnerabilities if v.get('verified'))
        verified_stored = sum(1 for v in self.stored_vulnerabilities if v.get('verified'))
        total_verified = verified_reflected + verified_dom + verified_stored
        
        if total_verified == 0:
            print(f"{Fore.GREEN}✅ No XSS vulnerabilities found!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Found {total_verified} VERIFIED XSS vulnerabilities!{Style.RESET_ALL}")
            
            if verified_reflected > 0:
                print(f"\n{Fore.CYAN}--- Reflected XSS ({verified_reflected} verified) ---{Style.RESET_ALL}")
                for vuln in self.reflected_vulnerabilities:
                    if vuln.get('verified'):
                        print(f"{Fore.YELLOW}URL: {vuln['url']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Parameter: {vuln['parameter']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Payload: {vuln['payload'][:80]}...{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}✓ VERIFIED{Style.RESET_ALL}")
                        print()
            
            if verified_dom > 0:
                print(f"\n{Fore.CYAN}--- DOM-based XSS ({verified_dom} verified) ---{Style.RESET_ALL}")
                for vuln in self.dom_vulnerabilities:
                    if vuln.get('verified'):
                        print(f"{Fore.YELLOW}URL: {vuln['url']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Parameter: {vuln['parameter']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Payload: {vuln['payload'][:80]}...{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}✓ VERIFIED{Style.RESET_ALL}")
                        print()
            
            if verified_stored > 0:
                print(f"\n{Fore.CYAN}--- Stored XSS ({verified_stored} verified) ---{Style.RESET_ALL}")
                for vuln in self.stored_vulnerabilities:
                    if vuln.get('verified'):
                        print(f"{Fore.YELLOW}URL: {vuln['url']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Parameter: {vuln['parameter']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Payload: {vuln['payload'][:80]}...{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}✓ VERIFIED{Style.RESET_ALL}")
                        print()
        
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    def cleanup(self):
        """Clean up resources"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

def main():
    parser = argparse.ArgumentParser(
        description='Advanced XSS Scanner with Multiple Scan Modes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -u "http://example.com/search?query=" -w payloads.txt -s r
  %(prog)s -u "http://test.com/page.php?id=" -w payloads.txt -s d
  %(prog)s -u "http://site.com/index.php?incl=_search.php&searchstring=" -w payloads.txt -s s
  %(prog)s -u "http://example.com/page.php?param=" -w payloads.txt -s rds
  %(prog)s -uf urls.txt -w payloads.txt -s r
  %(prog)s -u "http://example.com/page.php?param=" -w payloads.txt -s r -p param
        '''
    )
    
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-uf', '--url-file', help='File with a list of URLs to scan')
    parser.add_argument('-w', '--payload-file', help='Payload file', required=True)
    parser.add_argument('-s', '--scan-mode', help='Scan mode: r (Reflected), d (DOM), s (Stored), rds (all)', default='r', choices=['r', 'd', 's', 'rds'])
    parser.add_argument('-p', '--parameter', help='Specific parameter to test (optional)')
    
    args = parser.parse_args()
    
    if not args.url and not args.url_file:
        print(f"{Fore.RED}[-] Please provide either a URL (-u) or URL file (-uf){Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    scanner = AdvancedXSSScanner()
    
    try:
        # Show banner
        scanner.show_banner()
        
        # Load payloads
        scanner.print_loading("Loading XSS payloads...")
        scanner.load_payloads(args.payload_file)
        
        # Get URLs to scan
        urls = []
        if args.url:
            urls = [args.url]
        elif args.url_file:
            scanner.print_loading("Loading URLs from file...")
            urls = scanner.load_urls(args.url_file)
        
        # Parse scan mode
        scan_reflected = 'r' in args.scan_mode
        scan_dom = 'd' in args.scan_mode
        scan_stored = 's' in args.scan_mode
        
        # Scan each URL
        for i, url in enumerate(urls, 1):
            print(f"\n{Fore.MAGENTA}[🔍] Scanning URL {i}/{len(urls)}: {url}{Style.RESET_ALL}")
            
            if scan_reflected:
                scanner.print_info("Scanning for Reflected XSS...")
                scanner.scan_reflected_xss(url, args.parameter)
            
            if scan_dom:
                scanner.print_info("Scanning for DOM-based XSS...")
                scanner.scan_dom_xss(url, args.parameter)
            
            if scan_stored:
                scanner.print_info("Scanning for Stored XSS...")
                scanner.scan_stored_xss(url, args.parameter)
        
        # Generate report
        scanner.print_loading("Generating final report...")
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    main()
