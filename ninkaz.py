import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from collections import defaultdict
import argparse
import sys
import re
import json
import os
import signal
import random
from datetime import datetime
from difflib import unified_diff

class WebSiteCrawler:
    def __init__(self, base_url, delay=1, verbose=False, user_agent=None, rate_limit=None,
             checkpoint_file="crawler_checkpoint.json", single_file=False, max_depth=None,
             include_pattern=None, exclude_pattern=None, scan_secrets=False,
             analyze_headers=False, stealth=False, wordlist=None, detect_tech=False,
             proxy=None, format_output='txt', cookies=None, custom_headers=None,
             scan_custom_headers_flag=False):
        """
        Initialise le crawler avec toutes les options
        """
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.delay = delay
        self.verbose = verbose
        self.checkpoint_file = checkpoint_file
        self.single_file = single_file
        self.max_depth = max_depth
        self.include_pattern = re.compile(include_pattern) if include_pattern else None
        self.exclude_pattern = re.compile(exclude_pattern) if exclude_pattern else None
        self.scan_secrets = scan_secrets
        self.analyze_headers = analyze_headers
        self.scan_custom_headers_flag = scan_custom_headers_flag          
        self.stealth = stealth
        self.wordlist = wordlist
        self.detect_tech = detect_tech
        self.proxy = proxy
        self.format_output = format_output
        self.cookies = self._parse_cookies(cookies) if cookies else {}
        self.custom_headers = self._parse_custom_headers(custom_headers) if custom_headers else {}

        # User-Agents pour mode stealth
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        ]

        if user_agent:
            self.current_user_agent = user_agent
        elif stealth:
            self.current_user_agent = random.choice(self.user_agents)
        else:
            self.current_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

        self.rate_limit = rate_limit
        self.request_times = []

        self.visited_urls = set()
        self.internal_pages = set()
        self.external_urls = set()
        self.interesting_files = set()
        self.directories_to_explore = set()
        self.urls_from_files = defaultdict(set)
        self.juicy_targets = []
        self.secrets_found = []
        self.headers_info = defaultdict(dict)
        self.custom_headers_found = []
        self.technologies = set()
        self.url_depths = {}

        self.interesting_extensions = {
            '.js', '.json', '.xml', '.txt', '.log', '.bak', '.old',
            '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
            '.sh', '.bat', '.sql', '.db', '.config', '.env', '.git',
            '.svn', '.zip', '.tar', '.gz', '.rar', '.7z', '.html', '.htm'
        }

        self.ignored_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
            '.css', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
            '.avi', '.mov', '.pdf', '.doc', '.docx', '.bmp', '.tiff'
        }

        self.parseable_extensions = {
            '.js', '.json', '.xml', '.txt', '.html', '.htm', '.php',
            '.asp', '.aspx', '.jsp', '.css', '.config', '.env', '.log'
        }

        self.juicy_patterns = [
            r'api[/_-]?key', r'secret', r'password', r'passwd', r'token',
            r'auth', r'admin', r'config', r'\.env', r'\.git', r'\.sql',
            r'backup', r'\.bak', r'\.old', r'debug', r'test', r'staging',
            r'dev', r'swagger', r'graphql', r'/api/v\d+/', r'credentials',
            r'private', r'internal',
        ]

        self.secret_patterns = {
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Password (Direct)': r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{6,})["\']',
            'Password ($scope)': r'\$scope\.password\s*=\s*["\']([^"\']{6,})["\']',
            'Email ($scope)': r'\$scope\.email\s*=\s*["\']([^"\']{6,})["\']',
            
            # ===== PATTERNS GÉNÉRIQUES POUR API KEYS =====
            'API Key (Generic)': r'(?:api[_-]?key|apikey|api_key|access_key|secret_key|app_key|app_secret|client_key|client_secret)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{15,})["\']?',
            'API Key (camelCase)': r'(?:defaultXApi|defaultApi|apiKey|appKey|clientKey|secretKey|accessKey)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{15,})["\']?',
            'API Key (snake_case)': r'(?:default_api|default_x_api|api_secret|app_secret|client_secret|access_secret)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{15,})["\']?',
            'API Key (UPPERCASE)': r'(?:DEFAULT_API|DEFAULT_X_API|API_KEY|API_SECRET|APP_KEY|CLIENT_KEY)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{15,})["\']?',
            'Generic Token Pattern': r'(?:token|auth_token|access_token|refresh_token|bearer_token|api_token)\s*[=:]\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
            
            # ===== PATTERNS SPÉCIFIQUES =====
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
            'Bearer Token': r'Bearer\s+([a-zA-Z0-9\-_\.]{20,})',
            'JWT Token': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'Database URL': r'(?:mysql|postgres|mongodb)://[^\s\'"]+',
            'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'Stripe Key': r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
            
            # ===== PATTERNS GÉNÉRIQUES SUPPLÉMENTAIRES =====
            'Generic Secret': r'(?:secret|password|passwd|pwd|pass|credential|credentials|auth|authorization)\s*[=:]\s*["\']([^"\']{8,})["\']',
            'URL Credentials': r'(?:https?://)?[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]{6,}@',
            'Firebase Config': r'apiKey["\']?\s*[=:]\s*["\']([^"\']{30,})["\']',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Hex String (Potential Secret)': r'(?:secret|key|token|password)\s*[=:]\s*["\']?([a-f0-9]{32,})["\']?',
            'Username/Password Pair': r'(?:username|user|login)\s*[=:]\s*["\']([^"\']{3,})["\'].*?(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',
        }

        self.tech_patterns = {
            'React': [r'react', r'_react', r'__REACT'],
            'Angular': [r'angular', r'ng-app', r'ng-controller'],
            'Vue.js': [r'vue', r'__vue__', r'v-app'],
            'jQuery': [r'jquery', r'\$\.ajax'],
            'Bootstrap': [r'bootstrap\.css', r'bootstrap\.js'],
            'WordPress': [r'/wp-content/', r'/wp-admin/', r'wp-includes'],
            'Drupal': [r'/sites/default/', r'/modules/', r'/themes/'],
            'Joomla': [r'/components/', r'/modules/', r'/templates/'],
            'Django': [r'/static/', r'/media/', r'csrf'],
            'Flask': [r'flask', r'werkzeug'],
            'Laravel': [r'/storage/', r'/vendor/', r'laravel'],
            'Node.js': [r'node_modules', r'package\.json'],
            'Express': [r'express', r'middleware'],
            'ASP.NET': [r'\.aspx', r'\.asmx', r'web\.config'],
            'Java': [r'\.jsp', r'\.jar', r'tomcat'],
        }

        self.interrupted = False
        signal.signal(signal.SIGINT, self.signal_handler)

    def scan_custom_headers(self, headers, source_url):
        """Scanne les headers HTTP pour détecter les secrets ET les headers custom"""
        if not self.scan_custom_headers_flag:
            return
    
        # Patterns pour détecter les secrets dans les headers
        header_secret_patterns = {
            'Authorization': r'Authorization\s*[=:]\s*(?:Bearer\s+)?([a-zA-Z0-9\-_.]{20,})',
            'X-API-Key': r'X-API-Key\s*[=:]\s*([a-zA-Z0-9\-_]{15,})',
            'X-APP-ID': r'X-APP-ID\s*[=:]\s*([a-zA-Z0-9\-]{10,})',
            'X-Token': r'X-Token\s*[=:]\s*([a-zA-Z0-9\-_]{15,})',
            'X-Access-Token': r'X-Access-Token\s*[=:]\s*([a-zA-Z0-9\-_]{15,})',
            'X-Auth-Token': r'X-Auth-Token\s*[=:]\s*([a-zA-Z0-9\-_]{15,})',
            'X-Custom-Auth': r'X-Custom-Auth\s*[=:]\s*([a-zA-Z0-9\-_]{15,})',
            'Cookie': r'(?:session|token|auth|key|secret)\s*=\s*([a-zA-Z0-9\-_]{10,})',
        }
    
        # Headers custom à tracker (sans secrets)
        custom_header_prefixes = ['X-', 'Custom-', 'App-', 'API-']
        
        secrets_found_count = 0
        custom_headers_found = []
    
        for header_name, header_value in headers.items():
            header_str = f"{header_name}: {header_value}"
            
            # 1️⃣ SCAN DES SECRETS DANS LES HEADERS
            for secret_type, pattern in header_secret_patterns.items():
                try:
                    matches = re.finditer(pattern, header_str, re.IGNORECASE)
                    
                    for match in matches:
                        secret_value = match.group(0)
                        
                        masked_value = secret_value[:10] + '*' * max(0, len(secret_value) - 20) + secret_value[-10:] if len(secret_value) > 20 else '*' * len(secret_value)
                        
                        self.secrets_found.append({
                            'type': f'Header: {secret_type}',
                            'url': source_url,
                            'value': masked_value,
                            'full_value': secret_value,
                            'severity': 'CRITICAL'
                        })
                        
                        print(f"  🔐 SECRET DÉTECTÉ (Header: {secret_type}): {masked_value}")
                        secrets_found_count += 1
                        
                except Exception as e:
                    self.log(f"Erreur avec pattern header {secret_type}: {e}", "WARNING")
    
            # 2️⃣ DÉTECTION DES HEADERS CUSTOM (sans secrets)
            for prefix in custom_header_prefixes:
                if header_name.startswith(prefix):
                    custom_headers_found.append({
                        'name': header_name,
                        'value': header_value,
                        'url': source_url
                    })
                    print(f"  📋 HEADER CUSTOM DÉTECTÉ: {header_name}: {header_value}")
                    break
    
        # Stocker les headers custom trouvés
        if custom_headers_found:
            if not hasattr(self, 'custom_headers_found'):
                self.custom_headers_found = []
            self.custom_headers_found.extend(custom_headers_found)
    
        if secrets_found_count == 0 and len(custom_headers_found) == 0 and self.verbose:
            print(f"  ℹ️  Aucun secret ou header custom détecté")


    def _parse_cookies(self, cookies_str):
        """Parse les cookies depuis une chaîne"""
        cookies_dict = {}
        if not cookies_str:
            return cookies_dict
        try:
            for cookie in cookies_str.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookies_dict[name.strip()] = value.strip()
            if self.verbose:
                print(f"🍪 {len(cookies_dict)} cookie(s) chargé(s)")
        except Exception as e:
            print(f"⚠️  Erreur parsing cookies: {e}")
        return cookies_dict

    def _parse_custom_headers(self, headers_str):
        """Parse les headers personnalisés"""
        headers_dict = {}
        if not headers_str:
            return headers_dict
        try:
            for header in headers_str.split(';'):
                header = header.strip()
                if ':' in header:
                    name, value = header.split(':', 1)
                    headers_dict[name.strip()] = value.strip()
            if self.verbose:
                print(f"📋 {len(headers_dict)} header(s) personnalisé(s) chargé(s)")
        except Exception as e:
            print(f"⚠️  Erreur parsing headers: {e}")
        return headers_dict

    def signal_handler(self, sig, frame):
        """Gère l'interruption (Ctrl+C) pour sauvegarder l'état"""
        if self.interrupted:
            print("\n\n🛑 Arrêt forcé sans sauvegarde !")
            os._exit(1)

        self.interrupted = True
        print("\n\n⏸️  Interruption détectée (Ctrl+C)")

        if not self.single_file:
            print("💾 Sauvegarde de l'état actuel...")
            self.save_checkpoint()
            print(f"✅ État sauvegardé dans {self.checkpoint_file}")
            print("🔄 Pour reprendre, relancez le script avec --resume")

        print("⚠️  Appuyez à nouveau sur Ctrl+C pour forcer l'arrêt")
        os._exit(0)

    def save_checkpoint(self):
        """Sauvegarde l'état actuel du crawl"""
        checkpoint = {
            'base_url': self.base_url,
            'visited_urls': list(self.visited_urls),
            'internal_pages': list(self.internal_pages),
            'external_urls': list(self.external_urls),
            'interesting_files': list(self.interesting_files),
            'directories_to_explore': list(self.directories_to_explore),
            'urls_from_files': {k: list(v) for k, v in self.urls_from_files.items()},
            'juicy_targets': self.juicy_targets,
            'secrets_found': self.secrets_found,
            'technologies': list(self.technologies),
        }

        with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, indent=2, ensure_ascii=False)

    def load_checkpoint(self):
        """Charge l'état sauvegardé"""
        if not os.path.exists(self.checkpoint_file):
            print(f"❌ Fichier de checkpoint {self.checkpoint_file} introuvable")
            return False

        try:
            with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)

            if checkpoint['base_url'] != self.base_url:
                print(f"⚠️  Le checkpoint est pour {checkpoint['base_url']}, pas {self.base_url}")
                response = input("Voulez-vous continuer quand même ? (o/n): ")
                if response.lower() != 'o':
                    return False

            self.visited_urls = set(checkpoint['visited_urls'])
            self.internal_pages = set(checkpoint['internal_pages'])
            self.external_urls = set(checkpoint['external_urls'])
            self.interesting_files = set(checkpoint['interesting_files'])
            self.directories_to_explore = set(checkpoint['directories_to_explore'])
            self.urls_from_files = defaultdict(set, {k: set(v) for k, v in checkpoint['urls_from_files'].items()})
            self.juicy_targets = checkpoint.get('juicy_targets', [])
            self.secrets_found = checkpoint.get('secrets_found', [])
            self.technologies = set(checkpoint.get('technologies', []))

            print(f"📂 État chargé depuis {self.checkpoint_file}")
            print(f"✓ {len(self.visited_urls)} URLs déjà visitées")
            print(f"⏳ {len(self.directories_to_explore)} URLs restantes à explorer")

            return True
        except Exception as e:
            print(f"❌ Erreur lors du chargement du checkpoint: {e}")
            return False

    def apply_rate_limit(self):
        """Applique le rate limiting si configuré"""
        if not self.rate_limit:
            return

        current_time = time.time()
        self.request_times = [t for t in self.request_times if current_time - t < 60]

        if len(self.request_times) >= self.rate_limit:
            sleep_time = 60 - (current_time - self.request_times[0])
            if sleep_time > 0:
                print(f"  ⏱️  Rate limit atteint ({self.rate_limit} req/min), pause de {sleep_time:.1f}s")
                time.sleep(sleep_time)
                self.request_times = []

        self.request_times.append(current_time)

    def get_random_delay(self):
        """Retourne un délai aléatoire en mode stealth"""
        if self.stealth:
            return self.delay + random.uniform(0, self.delay)
        return self.delay

    def rotate_user_agent(self):
        """Rotation du User-Agent en mode stealth"""
        if self.stealth:
            self.current_user_agent = random.choice(self.user_agents)

    def scan_for_secrets(self, content, source_url):
        """Scanne le contenu à la recherche de secrets"""
        if not self.scan_secrets:
            return
    
        secrets_found_count = 0
    
        for secret_type, pattern in self.secret_patterns.items():
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            
                for match in matches:
                    secret_value = match.group(0)
                
                    # Éviter les faux positifs (mots communs)
                    if secret_type == 'Email':
                        if any(x in secret_value.lower() for x in ['example.com', 'test.com', 'demo.com']):
                            continue
                
                    masked_value = secret_value[:10] + '*' * max(0, len(secret_value) - 20) + secret_value[-10:] if len(secret_value) > 20 else '*' * len(secret_value)
    
                    self.secrets_found.append({
                        'type': secret_type,
                        'url': source_url,
                        'value': masked_value,
                        'full_value': secret_value,
                        'severity': 'CRITICAL' if secret_type in ['AWS Key', 'Private Key', 'GitHub Token', 'Password ($scope)', 'Email ($scope)', 'X-APP-ID', 'X-API-KEY'] else 'HIGH'
                    })
                
                    print(f"  🔐 SECRET DÉTECTÉ ({secret_type}): {masked_value}")
                    secrets_found_count += 1
                
            except Exception as e:
                self.log(f"Erreur avec pattern {secret_type}: {e}", "WARNING")
    
        if secrets_found_count == 0 and self.verbose:
            print(f"  ℹ️  Aucun secret détecté")


    def detect_technologies(self, content, headers):
        """Détecte les technologies utilisées"""
        if not self.detect_tech:
            return

        content_lower = content.lower()

        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    self.technologies.add(tech)
                    break

        if 'Server' in headers:
            self.technologies.add(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            self.technologies.add(f"Framework: {headers['X-Powered-By']}")

    
    def analyze_http_headers(self, url, headers):
        """Capture et analyse les headers HTTP - Focus sécurité"""
        if not self.analyze_headers:
            return
    
        # Headers de sécurité critiques
        security_headers = {
            'Content-Security-Policy': 'CSP - Prévient les injections XSS',
            'X-Frame-Options': 'Clickjacking - Empêche l\'embedding en iframe',
            'X-Content-Type-Options': 'MIME sniffing - Force le type MIME',
            'Strict-Transport-Security': 'HSTS - Force HTTPS',
            'X-XSS-Protection': 'XSS - Protection navigateur',
            'Referrer-Policy': 'Referrer - Contrôle les infos de referer',
            'Permissions-Policy': 'Permissions - Contrôle les APIs du navigateur',
        }
    
        # Headers révélant des infos sensibles
        info_disclosure_headers = {
            'Server': '⚠️  Révèle le serveur web',
            'X-Powered-By': '⚠️  Révèle le framework',
            'X-AspNet-Version': '⚠️  Révèle la version ASP.NET',
            'X-Runtime-Version': '⚠️  Révèle la version runtime',
        }
    
        missing_headers = []
        info_disclosure = []
        suspicious_headers = []
    
        # 1️⃣ Vérifier les headers de sécurité manquants
        for header, description in security_headers.items():
            if header not in headers:
                missing_headers.append({
                    'header': header,
                    'description': description,
                    'severity': 'HIGH'
                })
    
        # 2️⃣ Détecter les infos sensibles révélées
        for header, risk in info_disclosure_headers.items():
            if header in headers:
                info_disclosure.append({
                    'header': header,
                    'value': headers[header],
                    'risk': risk,
                    'severity': 'MEDIUM'
                })
    
        # 3️⃣ Détecter les headers suspects (custom, non-standard)
        suspicious_prefixes = ['X-', 'Custom-', 'App-', 'Internal-', 'Debug-']
        for header_name, header_value in headers.items():
            if any(header_name.startswith(prefix) for prefix in suspicious_prefixes):
                if header_name not in security_headers and header_name not in info_disclosure_headers:
                    suspicious_headers.append({
                        'header': header_name,
                        'value': header_value,
                        'severity': 'LOW'
                    })
    
        # Stocker les infos
        self.headers_info[url] = {
            'missing_security_headers': missing_headers,
            'info_disclosure': info_disclosure,
            'suspicious_headers': suspicious_headers,
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
        }
    
        # Affichage console
        if missing_headers:
            print(f"  🔴 Headers manquants ({len(missing_headers)}):")
            for h in missing_headers[:3]:
                print(f"     ❌ {h['header']}")
            if len(missing_headers) > 3:
                print(f"     ... et {len(missing_headers) - 3} autres")
    
        if info_disclosure:
            print(f"  🟠 Info disclosure ({len(info_disclosure)}):")
            for h in info_disclosure[:2]:
                print(f"     ⚠️  {h['header']}: {h['value']}")

    
    def is_juicy_target(self, url):
        """Vérifie si l'URL est une cible prometteuse"""
        if not self.is_same_domain(url):
            return False

        url_lower = url.lower()

        for pattern in self.juicy_patterns:
            if re.search(pattern, url_lower):
                return True

        return False

    def add_juicy_target(self, url, reason):
        """Ajoute une URL aux cibles prometteuses"""
        for target in self.juicy_targets:
            if target['url'] == url:
                return

        self.juicy_targets.append({
            'url': url,
            'reason': reason
        })
        print(f"  🎯 JUICY TARGET: {url}")

    def log(self, message, level="INFO"):
        """Affiche un message si le mode verbeux est activé"""
        if self.verbose or level in ["ERROR", "FOUND", "SUCCESS"]:
            emoji_map = {
                "INFO": "ℹ️ ",
                "SUCCESS": "✅",
                "ERROR": "❌",
                "WARNING": "⚠️ ",
                "FOUND": "🔍"
            }
            emoji = emoji_map.get(level, "")
            print(f"{emoji} {message}")

    def is_same_domain(self, url):
        """Vérifie si l'URL appartient au même domaine"""
        parsed = urlparse(url)
        return parsed.netloc == self.parsed_base.netloc

    def should_include_url(self, url):
        """Vérifie si l'URL doit être incluse selon les patterns"""
        if self.include_pattern and not self.include_pattern.search(url):
            return False
        if self.exclude_pattern and self.exclude_pattern.search(url):
            return False
        return True

    def is_interesting_file(self, url):
        """Vérifie si le fichier est intéressant d'un point de vue bug bounty"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        for ext in self.interesting_extensions:
            if path.endswith(ext):
                return True
        return False

    def should_ignore(self, url):
        """Vérifie si l'URL doit être ignorée"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        for ext in self.ignored_extensions:
            if path.endswith(ext):
                return True
        return False

    def is_parseable(self, url):
        """Vérifie si le fichier peut être analysé pour extraire des URLs"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        for ext in self.parseable_extensions:
            if path.endswith(ext):
                return True
        return False

    def has_file_extension(self, path):
        """Vérifie si le chemin pointe vers un fichier (a une extension)"""
        last_part = path.rstrip('/').split('/')[-1]
        return '.' in last_part and last_part != '.' and last_part != '..'

    def extract_urls_from_content(self, content, source_url):
        """Extrait toutes les URLs trouvées dans le contenu d'un fichier"""
        found_urls = set()

        try:
            decoded_content = content
            unicode_escapes = re.findall(r'\\u([0-9a-fA-F]{4})', content)

            for escape in unicode_escapes:
                try:
                    char = chr(int(escape, 16))
                    decoded_content = decoded_content.replace(f'\\u{escape}', char)
                except:
                    pass
        except:
            decoded_content = content

        patterns = [
            r'https?://[^\s\'"<>]+',
            r'["\']([/][a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+)["\']',
            r'routerLink\s*=\s*["\']([/][^"\']+)["\']',
            r'href\s*=\s*["\']([/][^"\'#][^"\']*)["\']',
            r'src\s*=\s*["\']([/][^"\']+)["\']',
            r'["\']([/][a-zA-Z0-9_\-./]+)["\']',
        ]

        all_matches = set()

        for search_content in [content, decoded_content]:
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, search_content)

                    for match in matches:
                        if isinstance(match, tuple):
                            for m in match:
                                if m:
                                    all_matches.add(m)
                                    break
                        else:
                            all_matches.add(match)
                except Exception as e:
                    self.log(f"Erreur avec pattern {pattern}: {e}", "WARNING")

        for url in all_matches:
            url = url.strip().rstrip(',;)]\'"')

            if not url or url in ['/', '#', '']:
                continue

            if len(url) < 2:
                continue

            if url.startswith(('data:', 'javascript:', 'mailto:', 'tel:', 'about:', 'blob:')):
                continue

            if url.startswith('${') or url == '$':
                continue

            try:
                if url.startswith(('http://', 'https://')):
                    normalized_url = self.normalize_url(url)
                elif url.startswith('/'):
                    absolute_url = urljoin(source_url, url)
                    normalized_url = self.normalize_url(absolute_url)
                else:
                    absolute_url = urljoin(source_url, url)
                    normalized_url = self.normalize_url(absolute_url)

                parsed = urlparse(normalized_url)
                if parsed.scheme in ('http', 'https') and parsed.netloc:
                    if len(parsed.netloc) > 0 and '.' in parsed.netloc:
                        if self.should_include_url(normalized_url):
                            found_urls.add(normalized_url)

                            if self.is_juicy_target(normalized_url):
                                self.add_juicy_target(normalized_url, f"Pattern détecté dans {source_url}")
            except Exception as e:
                self.log(f"Erreur lors du traitement de l'URL '{url}': {e}", "WARNING")

        return found_urls

    def extract_parent_directories(self, url):
        """Extrait tous les répertoires parents d'une URL"""
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')

        if '${' in path:
            path = path.split('${')[0].rstrip('/')
            if not path or path == '/':
                return []

        if not path or path == '/':
            return []

        directories = []
        parts = path.split('/')

        end_index = len(parts)
        if self.has_file_extension(path):
            end_index = len(parts) - 1

        for i in range(1, end_index):
            dir_path = '/'.join(parts[:i+1])
            if dir_path:
                full_url = f"{parsed.scheme}://{parsed.netloc}{dir_path}/"
                directories.append(full_url)

        return directories

    def extract_directory_from_file(self, url):
        """Extrait le répertoire contenant un fichier"""
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')

        if self.has_file_extension(path):
            parts = path.split('/')
            if len(parts) > 1:
                dir_path = '/'.join(parts[:-1])
                if dir_path:
                    return f"{parsed.scheme}://{parsed.netloc}{dir_path}/"

        return None

    def normalize_url(self, url):
        """Normalise une URL pour éviter les doublons"""
        parsed = urlparse(url)
        url_without_fragment = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            url_without_fragment += f"?{parsed.query}"

        return url_without_fragment

    def fetch_page(self, url):
        """Récupère le contenu d'une page"""
        try:
            self.apply_rate_limit()
            self.rotate_user_agent()

            headers = {
                'User-Agent': self.current_user_agent
            }
            if self.custom_headers:
                headers.update(self.custom_headers)

            proxies = None
            if self.proxy:
                proxies = {
                    'http': self.proxy,
                    'https': self.proxy,
                }

            response = requests.get(url, headers=headers, cookies=self.cookies, timeout=10, allow_redirects=True, proxies=proxies)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            self.log(f"⏱️  Timeout: {url}", "WARNING")
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Erreur requête {url}: {e}", "WARNING")
            return None
        except Exception as e:
            self.log(f"❌ Erreur inattendue {url}: {e}", "ERROR")
            return None

    def extract_resources(self, url, html_content):
        """Extrait toutes les ressources d'une page HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        resources = set()

        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                resources.add(href)

        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            if src:
                resources.add(src)

        for script in soup.find_all('script'):
            if script.string:
                inline_urls = self.extract_urls_from_content(script.string, url)
                if inline_urls:
                    print(f"  📜 {len(inline_urls)} URL(s) trouvée(s) dans un script inline")
                    resources.update(inline_urls)

        for iframe in soup.find_all('iframe', src=True):
            src = iframe['src'].strip()
            if src:
                resources.add(src)

        for form in soup.find_all('form', action=True):
            action = form['action'].strip()
            if action:
                resources.add(action)

        for img in soup.find_all('img', src=True):
            src = img['src'].strip()
            if src:
                resources.add(src)

        for link in soup.find_all('link', href=True):
            href = link['href'].strip()
            if href:
                resources.add(href)

        for obj in soup.find_all(['object', 'embed']):
            src = obj.get('data') or obj.get('src', '')
            if src:
                resources.add(src.strip())

        normalized = set()
        for resource in resources:
            if resource:
                try:
                    if resource.startswith(('http://', 'https://')) and '${' in resource:
                        normalized.add(resource)
                        continue

                    absolute_url = urljoin(url, resource)
                    normalized_url = self.normalize_url(absolute_url)

                    parsed = urlparse(normalized_url)
                    if parsed.scheme in ('http', 'https') and parsed.netloc:
                        if self.should_include_url(normalized_url):
                            normalized.add(normalized_url)
                except Exception as e:
                    self.log(f"Erreur normalisation {resource}: {e}", "WARNING")

        return normalized

    def add_parent_directories_to_explore(self, url):
        """Ajoute tous les répertoires parents à la liste d'exploration"""
        if self.single_file:
            return

        parent_dirs = self.extract_parent_directories(url)
        for directory in parent_dirs:
            normalized_dir = self.normalize_url(directory)
            if normalized_dir not in self.visited_urls:
                self.directories_to_explore.add(normalized_dir)

    def add_file_directory_to_explore(self, url):
        """Ajoute le répertoire contenant un fichier à la liste d'exploration"""
        if self.single_file:
            return

        directory = self.extract_directory_from_file(url)
        if directory:
            normalized_dir = self.normalize_url(directory)
            if normalized_dir not in self.visited_urls:
                self.directories_to_explore.add(normalized_dir)

    def get_total_urls_to_explore(self):
        """Calcule le nombre total d'URLs à explorer"""
        return len(self.visited_urls) + len(self.directories_to_explore)

    def process_discovered_urls(self, urls, source_file):
        """Traite les URLs découvertes dans un fichier"""
        for url in urls:
            if source_file:
                self.urls_from_files[source_file].add(url)

            if '${' in url:
                self.add_parent_directories_to_explore(url)

                if not self.is_same_domain(url):
                    clean_url = re.sub(r'\$\{[^}]+\}', '[VAR]', url)
                    self.external_urls.add(clean_url)
                continue

            if url in self.visited_urls:
                continue

            if self.is_same_domain(url):
                self.add_parent_directories_to_explore(url)

                if self.has_file_extension(urlparse(url).path):
                    self.add_file_directory_to_explore(url)

                if self.should_ignore(url):
                    continue

                if self.is_interesting_file(url):
                    self.interesting_files.add(url)
                    print(f"  📄 Fichier intéressant: {url}")

                    if self.is_juicy_target(url):
                        self.add_juicy_target(url, f"Fichier intéressant trouvé dans {source_file}")

                    if not self.single_file:
                        self.directories_to_explore.add(url)
                else:
                    if url not in self.internal_pages:
                        self.internal_pages.add(url)
                        if not self.single_file:
                            self.directories_to_explore.add(url)
            else:
                self.external_urls.add(url)

    def load_wordlist(self):
        """Charge une wordlist pour fuzzing de répertoires"""
        if not self.wordlist or not os.path.exists(self.wordlist):
            return []

        try:
            with open(self.wordlist, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"📚 Wordlist chargée: {len(paths)} chemins")
            return paths
        except Exception as e:
            print(f"❌ Erreur lors du chargement de la wordlist: {e}")
            return []

    def fuzz_directories(self, base_url, wordlist):
        """Teste les chemins de la wordlist"""
        if not wordlist:
            return

        print(f"\n🔨 Fuzzing de répertoires avec wordlist...")
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in wordlist:
            if self.interrupted:
                break

            path = path.strip('/')
            test_url = f"{base}/{path}"

            if test_url in self.visited_urls:
                continue

            try:
                self.apply_rate_limit()
                self.rotate_user_agent()

                headers = {'User-Agent': self.current_user_agent}
                if self.custom_headers:
                    headers.update(self.custom_headers)
                proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None

                response = requests.head(test_url, headers=headers, cookies=self.cookies, timeout=5, allow_redirects=True, proxies=proxies)

                if response.status_code < 400:
                    print(f"  ✅ [{response.status_code}] {test_url}")
                    self.directories_to_explore.add(test_url)

                    if self.is_juicy_target(test_url):
                        self.add_juicy_target(test_url, "Découvert via fuzzing de wordlist")
            except:
                pass

    def crawl_single_file(self, url):
        """Analyse un seul fichier sans exploration récursive"""
        url = self.normalize_url(url)
        self.visited_urls.add(url)

        print(f"📋 Analyse du fichier unique: {url}\n")

        response = self.fetch_page(url)
        if not response:
            print("❌ Impossible de récupérer le fichier")
            return

        content_type = response.headers.get('Content-Type', '').lower()

        self.analyze_http_headers(url, response.headers)
        self.scan_custom_headers(response.headers, url)

        if self.is_parseable(url):
            try:
                try:
                    content = response.text
                except:
                    content = response.content.decode('utf-8', errors='ignore')

                self.scan_for_secrets(content, url)

                self.detect_technologies(content, response.headers)

                found_urls = self.extract_urls_from_content(content, url)

                if found_urls:
                    print(f"🔗 {len(found_urls)} URL(s) trouvée(s) dans le fichier\n")
                    self.process_discovered_urls(found_urls, url)
                else:
                    print("ℹ️  Aucune URL trouvée dans le fichier\n")

            except Exception as e:
                self.log(f"Erreur analyse {url}: {e}", "ERROR")
        else:
            print(f"⚠️  Le fichier n'est pas analysable (extension non supportée)\n")

        if self.is_interesting_file(url):
            self.interesting_files.add(url)

            if self.is_juicy_target(url):
                self.add_juicy_target(url, "Fichier analysé avec pattern sensible")

    def crawl(self, url, depth=0):
        """Crawle récursivement une URL"""
        if self.max_depth and depth > self.max_depth:
            return

        url = self.normalize_url(url)

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)
        self.url_depths[url] = depth

        total = self.get_total_urls_to_explore()
        current = len(self.visited_urls)
        print(f"🕷️  Exploration [{current} / {total}] (profondeur: {depth}): {url}")

        if current % 50 == 0 and not self.single_file:
            self.save_checkpoint()
            print(f"  💾 Checkpoint automatique sauvegardé")

        time.sleep(self.get_random_delay())

        response = self.fetch_page(url)
        if not response:
            return

        content_type = response.headers.get('Content-Type', '').lower()

        self.analyze_http_headers(url, response.headers)
        self.scan_custom_headers(response.headers, url)

        if self.is_parseable(url):
            try:
                try:
                    content = response.text
                except:
                    content = response.content.decode('utf-8', errors='ignore')

                self.scan_for_secrets(content, url)

                self.detect_technologies(content, response.headers)

                found_urls = self.extract_urls_from_content(content, url)

                if found_urls:
                    print(f"  🔗 {len(found_urls)} URL(s) trouvée(s)")
                    self.process_discovered_urls(found_urls, url)

            except Exception as e:
                self.log(f"Erreur analyse {url}: {e}", "ERROR")

        self.add_parent_directories_to_explore(url)

        if self.has_file_extension(urlparse(url).path):
            self.add_file_directory_to_explore(url)

        if self.is_interesting_file(url):
            self.interesting_files.add(url)
            print(f"  📄 Fichier intéressant: {url}")

            if self.is_juicy_target(url):
                self.add_juicy_target(url, "Fichier intéressant avec pattern sensible")

        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
            return

        resources = self.extract_resources(url, response.text)

        for resource in resources:
            if '${' in resource:
                self.urls_from_files[url].add(resource)
                self.add_parent_directories_to_explore(resource)
                if not self.is_same_domain(resource):
                    clean_url = re.sub(r'\$\{[^}]+\}', '[VAR]', resource)
                    self.external_urls.add(clean_url)
                continue

            if resource in self.visited_urls:
                continue

            if self.is_same_domain(resource):
                self.add_parent_directories_to_explore(resource)

                if self.has_file_extension(urlparse(resource).path):
                    self.add_file_directory_to_explore(resource)

                if self.should_ignore(resource):
                    continue

                if self.is_interesting_file(resource):
                    self.interesting_files.add(resource)
                    print(f"  📄 Fichier intéressant: {resource}")

                    if self.is_juicy_target(resource):
                        self.add_juicy_target(resource, f"Fichier intéressant trouvé dans {url}")

                    self.directories_to_explore.add(resource)
                else:
                    self.internal_pages.add(resource)
                    self.crawl(resource, depth + 1)
            else:
                self.external_urls.add(resource)

    def explore_directories(self):
        """Explore tous les répertoires découverts"""
        print("\n📂 Exploration des répertoires découverts...")

        iteration = 0
        max_iterations = 100

        while self.directories_to_explore and iteration < max_iterations:
            iteration += 1
            print(f"\n🔄 Itération {iteration} - {len(self.directories_to_explore)} répertoires à explorer")

            dirs_to_process = list(self.directories_to_explore)
            self.directories_to_explore.clear()

            for directory in dirs_to_process:
                if directory not in self.visited_urls and self.is_same_domain(directory):
                    depth = self.url_depths.get(directory, 1)
                    self.crawl(directory, depth)

            if not self.directories_to_explore:
                break

        if iteration >= max_iterations:
            print(f"⚠️  Limite d'itérations atteinte ({max_iterations})")

        print(f"\n✅ Exploration des répertoires terminée après {iteration} itération(s)")

    def start(self, resume=False, diff_file=None):
        """Démarre le crawl"""
        if self.single_file:
            self.crawl_single_file(self.base_url)
            self.generate_report()
            return

        if resume:
            if not self.load_checkpoint():
                print("❌ Impossible de reprendre, démarrage d'un nouveau crawl")
                resume = False

        if not resume:
            print(f"🚀 Démarrage du crawl de: {self.base_url}\n")
            self.crawl(self.base_url, depth=0)
        else:
            print(f"🔄 Reprise du crawl de: {self.base_url}\n")
            print(f"⏳ Reprise avec {len(self.directories_to_explore)} URLs en attente\n")

        if self.wordlist:
            wordlist_paths = self.load_wordlist()
            self.fuzz_directories(self.base_url, wordlist_paths)

        self.explore_directories()
        self.generate_report()

        if diff_file:
            self.compare_with_previous(diff_file)

    def compare_with_previous(self, previous_file):
        """Compare avec un crawl précédent"""
        if not os.path.exists(previous_file):
            print(f"❌ Fichier de comparaison {previous_file} introuvable")
            return

        try:
            with open(previous_file, 'r', encoding='utf-8') as f:
                previous_data = json.load(f)

            previous_urls = set(previous_data.get('internal_pages', []))
            current_urls = self.internal_pages

            new_urls = current_urls - previous_urls
            removed_urls = previous_urls - current_urls

            print("\n" + "="*80)
            print("📊 COMPARAISON AVEC CRAWL PRÉCÉDENT")
            print("="*80)

            if new_urls:
                print(f"\n✨ Nouvelles URLs ({len(new_urls)}):")
                for url in sorted(new_urls)[:20]:
                    print(f"  ➕ {url}")
                if len(new_urls) > 20:
                    print(f"  ... et {len(new_urls) - 20} autres")

            if removed_urls:
                print(f"\n❌ URLs supprimées ({len(removed_urls)}):")
                for url in sorted(removed_urls)[:20]:
                    print(f"  ➖ {url}")
                if len(removed_urls) > 20:
                    print(f"  ... et {len(removed_urls) - 20} autres")

            if not new_urls and not removed_urls:
                print("\n✅ Aucun changement détecté")

        except Exception as e:
            print(f"❌ Erreur lors de la comparaison: {e}")

    def generate_report(self):
        """Génère un rapport des ressources découvertes"""
        print("\n" + "="*80)
        print("📋 RAPPORT DE CARTOGRAPHIE WEB")
        print("="*80)
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🌐 Site: {self.base_url}")

        if self.single_file:
            print(f"📄 Mode: Fichier unique")
        if self.max_depth:
            print(f"📏 Profondeur max: {self.max_depth}")
        if self.include_pattern:
            print(f"✅ Filtre inclusion: {self.include_pattern.pattern}")
        if self.exclude_pattern:
            print(f"❌ Filtre exclusion: {self.exclude_pattern.pattern}")

        print("\n" + "="*80)
        print("🔐 SECRETS DÉTECTÉS")
        print("="*80)

        if self.secrets_found:
            print(f"\n⚠️  {len(self.secrets_found)} secret(s) trouvé(s):\n")

            by_severity = defaultdict(list)
            for secret in self.secrets_found:
                by_severity[secret['severity']].append(secret)

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                if severity in by_severity:
                    emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
                    print(f"\n{emoji} {severity}:")
                    for secret in by_severity[severity][:10]:
                        print(f"  🔑 {secret['type']}: {secret['url']}")
                        print(f"     💾 Valeur complète: {secret['full_value']}")
                    if len(by_severity[severity]) > 10:
                        print(f"  ... et {len(by_severity[severity]) - 10} autres")
        else:
            print("\n✅ Aucun secret détecté")

        print("\n" + "="*80)
        print("🎯 JUICY TARGETS - CIBLES PROMETTEUSES")
        print("="*80)

        if hasattr(self, 'custom_headers_found') and self.custom_headers_found:
            print(f"\n📋 {len(self.custom_headers_found)} header(s) personnalisé(s) trouvé(s):\n")
            
            by_name = defaultdict(list)
            for header in self.custom_headers_found:
                by_name[header['name']].append(header)
            
            for header_name, occurrences in sorted(by_name.items()):
                print(f"\n  📌 {header_name}:")
                for occurrence in occurrences[:5]:
                    print(f"     🌐 {occurrence['url']}")
                    print(f"     💾 Valeur: {occurrence['value']}")
                if len(occurrences) > 5:
                    print(f"     ... et {len(occurrences) - 5} autres occurrences")
        else:
            print("\n✅ Aucun header personnalisé détecté")

        if self.juicy_targets:
            print(f"\n🎪 {len(self.juicy_targets)} cible(s) prometteuse(s):\n")

            by_reason = defaultdict(list)
            for target in self.juicy_targets:
                by_reason[target['reason']].append(target['url'])

            for reason, urls in sorted(by_reason.items()):
                print(f"\n🎯 {reason} ({len(urls)} URL(s)):")
                for url in sorted(set(urls))[:10]:
                    print(f"   🔗 {url}")
                if len(urls) > 10:
                    print(f"   ... et {len(urls) - 10} autres")
        else:
            print("\n✅ Aucune cible prometteuse détectée")

        print("\n" + "="*80)
        print("🛠️  TECHNOLOGIES DÉTECTÉES")
        print("="*80)

        if self.technologies:
            print(f"\n🔧 {len(self.technologies)} technologie(s) détectée(s):\n")
            for tech in sorted(self.technologies):
                print(f"  ⚙️  {tech}")
        else:
            print("\n✅ Aucune technologie détectée")

        print("\n" + "="*80)
        print("🔒 ANALYSE DES HEADERS DE SÉCURITÉ")
        print("="*80)
        
        if self.headers_info:
            print(f"\n📊 {len(self.headers_info)} URL(s) analysée(s):\n")
        
            total_missing = 0
            total_disclosure = 0
            total_suspicious = 0
            
            for url, info in list(self.headers_info.items())[:10]:
                has_issues = False
                
                # Headers manquants
                if info.get('missing_security_headers'):
                    if not has_issues:
                        print(f"\n🌐 {url}")
                        has_issues = True
                    
                    print(f"   🔴 Headers manquants ({len(info['missing_security_headers'])}):")
                    for header in info['missing_security_headers'][:3]:
                        print(f"      ❌ {header['header']}")
                    if len(info['missing_security_headers']) > 3:
                        print(f"      ... et {len(info['missing_security_headers']) - 3} autres")
                    total_missing += len(info['missing_security_headers'])
                
                # Info disclosure
                if info.get('info_disclosure'):
                    if not has_issues:
                        print(f"\n🌐 {url}")
                        has_issues = True
                    
                    print(f"   🟠 Infos sensibles révélées ({len(info['info_disclosure'])}):")
                    for header in info['info_disclosure'][:2]:
                        print(f"      ⚠️  {header['header']}: {header['value']}")
                    total_disclosure += len(info['info_disclosure'])
                
                # Headers suspects
                if info.get('suspicious_headers'):
                    if not has_issues:
                        print(f"\n🌐 {url}")
                        has_issues = True
                    
                    print(f"   🟡 Headers suspects ({len(info['suspicious_headers'])}):")
                    for header in info['suspicious_headers'][:2]:
                        print(f"      📋 {header['header']}: {header['value']}")
                    if len(info['suspicious_headers']) > 2:
                        print(f"      ... et {len(info['suspicious_headers']) - 2} autres")
                    total_suspicious += len(info['suspicious_headers'])
        
            if len(self.headers_info) > 10:
                print(f"\n... et {len(self.headers_info) - 10} autres URLs")
        
            print(f"\n📈 Résumé sécurité headers:")
            print(f"   🔴 Headers manquants: {total_missing}")
            print(f"   🟠 Infos disclosure: {total_disclosure}")
            print(f"   🟡 Headers suspects: {total_suspicious}")
        else:
            print("\n✅ Aucun header analysé")


        print("\n" + "="*80)
        print("📎 FICHIERS INTÉRESSANTS")
        print("="*80)

        print(f"\n📦 {len(self.interesting_files)} fichier(s) intéressant(s):\n")
        for file in sorted(self.interesting_files):
            print(f"  📄 {file}")

        print("\n" + "="*80)
        print("🌍 URLS EXTERNES")
        print("="*80)

        print(f"\n🔗 {len(self.external_urls)} URL(s) externe(s):\n")
        for ext_url in sorted(self.external_urls)[:15]:
            print(f"  🌐 {ext_url}")
        if len(self.external_urls) > 15:
            print(f"  ... et {len(self.external_urls) - 15} autres")

        print("\n" + "="*80)
        print("📊 STATISTIQUES GLOBALES")
        print("="*80)

        total_urls_in_files = sum(len(urls) for urls in self.urls_from_files.values())

        print(f"\n📈 Résumé:")
        print(f"  ✓ Total URLs visitées: {len(self.visited_urls)}")
        print(f"  📄 Pages internes: {len(self.internal_pages)}")
        print(f"  📎 Fichiers intéressants: {len(self.interesting_files)}")
        print(f"  🎯 Juicy Targets: {len(self.juicy_targets)}")
        print(f"  🔐 Secrets détectés: {len(self.secrets_found)}")
        print(f"  🛠️  Technologies: {len(self.technologies)}")
        print(f"  🌍 URLs externes: {len(self.external_urls)}")
        print(f"  🔗 URLs trouvées dans fichiers: {total_urls_in_files}")
        print(f"  📊 Headers analysés: {len(self.headers_info)}")

    def export_to_file(self, filename="web_crawl_report.txt"):
        """Exporte les résultats dans un fichier"""
        if self.format_output == 'json':
            self.export_json(filename.replace('.txt', '.json'))
        else:
            self.export_txt(filename)

    
    def export_json(self, filename):
        """Exporte les résultats en JSON"""
        total_urls_in_files = sum(len(urls) for urls in self.urls_from_files.values())
    
        # Calcul des stats headers
        total_missing = sum(len(info.get('missing_security_headers', [])) 
                           for info in self.headers_info.values())
        total_disclosure = sum(len(info.get('info_disclosure', [])) 
                              for info in self.headers_info.values())
        total_suspicious = sum(len(info.get('suspicious_headers', [])) 
                              for info in self.headers_info.values())
    
        data = {
            'metadata': {
                'date': datetime.now().isoformat(),
                'site': self.base_url,
                'format_version': '1.0',
            },
            'statistics': {
                'total_urls_visited': len(self.visited_urls),
                'internal_pages': len(self.internal_pages),
                'interesting_files': len(self.interesting_files),
                'juicy_targets': len(self.juicy_targets),
                'secrets_found': len(self.secrets_found),
                'technologies': len(self.technologies),
                'external_urls': len(self.external_urls),
                'urls_in_files': total_urls_in_files,
                'custom_headers_found': len(self.custom_headers_found) if hasattr(self, 'custom_headers_found') else 0,
                'headers_analyzed': len(self.headers_info),
                'security_headers_missing': total_missing,
                'info_disclosure_found': total_disclosure,
                'suspicious_headers_found': total_suspicious,
            },
            'juicy_targets': self.juicy_targets,
            'secrets': self.secrets_found,
            'custom_headers': self.custom_headers_found if hasattr(self, 'custom_headers_found') else [],
            'technologies': list(self.technologies),
            'internal_pages': sorted(list(self.internal_pages)),
            'interesting_files': sorted(list(self.interesting_files)),
            'external_urls': sorted(list(self.external_urls)),
            'urls_from_files': {k: sorted(list(v)) for k, v in self.urls_from_files.items()},
            'headers_security_analysis': {k: v for k, v in self.headers_info.items()},
        }
    
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
        print(f"\n✅ Rapport JSON exporté dans: {filename}")



    def export_txt(self, filename):
        """Exporte les résultats en TXT"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("╔════════════════════════════════════════════════════════════════════════════╗\n")
            f.write("║                    📋 RAPPORT DE CRAWL WEB - BUG BOUNTY                     ║\n")
            f.write("╚════════════════════════════════════════════════════════════════════════════╝\n\n")
    
            f.write(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"🌐 Site: {self.base_url}\n\n")
    
            f.write("📊 STATISTIQUES\n")
            f.write("="*80 + "\n")
            f.write(f"✓ URLs visitées: {len(self.visited_urls)}\n")
            f.write(f"📄 Pages internes: {len(self.internal_pages)}\n")
            f.write(f"📎 Fichiers intéressants: {len(self.interesting_files)}\n")
            f.write(f"🎯 Cibles juteuses: {len(self.juicy_targets)}\n")
            f.write(f"🔐 Secrets trouvés: {len(self.secrets_found)}\n")
            f.write(f"🛠️  Technologies: {len(self.technologies)}\n")
            f.write(f"🌍 URLs externes: {len(self.external_urls)}\n")
            f.write(f"📋 Headers personnalisés: {len(self.custom_headers_found) if hasattr(self, 'custom_headers_found') else 0}\n")
            f.write(f"📊 URLs analysées (headers): {len(self.headers_info)}\n\n")
    
            # 🔐 SECRETS TROUVÉS
            if self.secrets_found:
                f.write("🔐 SECRETS TROUVÉS\n")
                f.write("="*80 + "\n")
                
                by_severity = defaultdict(list)
                for secret in self.secrets_found:
                    by_severity[secret['severity']].append(secret)
                
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    if severity in by_severity:
                        emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
                        f.write(f"\n{emoji} {severity} ({len(by_severity[severity])} secret(s)):\n")
                        for secret in by_severity[severity][:20]:
                            f.write(f"  🔑 Type: {secret['type']}\n")
                            f.write(f"     🌐 URL: {secret['url']}\n")
                            f.write(f"     💾 Valeur: {secret['full_value']}\n")
                            f.write(f"     🔒 Masqué: {secret['value']}\n\n")
                        if len(by_severity[severity]) > 20:
                            f.write(f"  ... et {len(by_severity[severity]) - 20} autres secrets\n\n")
                f.write("\n")
            else:
                f.write("🔐 SECRETS TROUVÉS\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucun secret détecté\n\n")
    
            # 📋 HEADERS PERSONNALISÉS
            if hasattr(self, 'custom_headers_found') and self.custom_headers_found:
                f.write("📋 HEADERS PERSONNALISÉS DÉTECTÉS\n")
                f.write("="*80 + "\n")
                
                by_name = defaultdict(list)
                for header in self.custom_headers_found:
                    by_name[header['name']].append(header)
                
                for header_name in sorted(by_name.keys()):
                    occurrences = by_name[header_name]
                    f.write(f"\n📌 {header_name} ({len(occurrences)} occurrence(s)):\n")
                    for occurrence in occurrences[:10]:
                        f.write(f"   🌐 URL: {occurrence['url']}\n")
                        f.write(f"   💾 Valeur: {occurrence['value']}\n")
                    if len(occurrences) > 10:
                        f.write(f"   ... et {len(occurrences) - 10} autres occurrences\n")
                f.write("\n")
            else:
                f.write("📋 HEADERS PERSONNALISÉS DÉTECTÉS\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucun header personnalisé détecté\n\n")
    
            # 🔒 ANALYSE DES HEADERS DE SÉCURITÉ
            if self.headers_info:
                f.write("🔒 ANALYSE DES HEADERS DE SÉCURITÉ\n")
                f.write("="*80 + "\n\n")
                
                total_missing = 0
                total_disclosure = 0
                total_suspicious = 0
                
                for url, info in list(self.headers_info.items())[:50]:
                    has_issues = False
                    
                    # Headers manquants
                    if info.get('missing_security_headers'):
                        if not has_issues:
                            f.write(f"🌐 {url}\n")
                            has_issues = True
                        
                        f.write(f"   🔴 Headers de sécurité manquants ({len(info['missing_security_headers'])}):\n")
                        for header in info['missing_security_headers']:
                            f.write(f"      ❌ {header['header']}\n")
                            f.write(f"         → {header['description']}\n")
                        total_missing += len(info['missing_security_headers'])
                    
                    # Info disclosure
                    if info.get('info_disclosure'):
                        if not has_issues:
                            f.write(f"🌐 {url}\n")
                            has_issues = True
                        
                        f.write(f"   🟠 Infos sensibles révélées ({len(info['info_disclosure'])}):\n")
                        for header in info['info_disclosure']:
                            f.write(f"      ⚠️  {header['header']}: {header['value']}\n")
                        total_disclosure += len(info['info_disclosure'])
                    
                    # Headers suspects
                    if info.get('suspicious_headers'):
                        if not has_issues:
                            f.write(f"🌐 {url}\n")
                            has_issues = True
                        
                        f.write(f"   🟡 Headers suspects ({len(info['suspicious_headers'])}):\n")
                        for header in info['suspicious_headers'][:3]:
                            f.write(f"      📋 {header['header']}: {header['value']}\n")
                        if len(info['suspicious_headers']) > 3:
                            f.write(f"      ... et {len(info['suspicious_headers']) - 3} autres\n")
                        total_suspicious += len(info['suspicious_headers'])
                    
                    if has_issues:
                        f.write("\n")
                
                if len(self.headers_info) > 50:
                    f.write(f"... et {len(self.headers_info) - 50} autres URLs\n\n")
                
                # Résumé
                f.write("📊 RÉSUMÉ SÉCURITÉ HEADERS:\n")
                f.write(f"   🔴 Headers manquants: {total_missing}\n")
                f.write(f"   🟠 Infos disclosure: {total_disclosure}\n")
                f.write(f"   🟡 Headers suspects: {total_suspicious}\n\n")
            else:
                f.write("🔒 ANALYSE DES HEADERS DE SÉCURITÉ\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucun header analysé\n\n")

            # 🎯 JUICY TARGETS
            if self.juicy_targets:
                f.write("🎯 CIBLES JUTEUSES (JUICY TARGETS)\n")
                f.write("="*80 + "\n")
                
                by_reason = defaultdict(list)
                for target in self.juicy_targets:
                    by_reason[target['reason']].append(target['url'])
                
                for reason in sorted(by_reason.keys()):
                    urls = by_reason[reason]
                    f.write(f"\n🎪 {reason} ({len(urls)} URL(s)):\n")
                    for url in sorted(set(urls))[:15]:
                        f.write(f"   🔗 {url}\n")
                    if len(urls) > 15:
                        f.write(f"   ... et {len(urls) - 15} autres\n")
                f.write("\n")
            else:
                f.write("🎯 CIBLES JUTEUSES (JUICY TARGETS)\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucune cible juteuse détectée\n\n")
    
            # 🛠️ TECHNOLOGIES DÉTECTÉES
            if self.technologies:
                f.write("🛠️  TECHNOLOGIES DÉTECTÉES\n")
                f.write("="*80 + "\n")
                for tech in sorted(self.technologies):
                    f.write(f"  ⚙️  {tech}\n")
                f.write("\n")
            else:
                f.write("🛠️  TECHNOLOGIES DÉTECTÉES\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucune technologie détectée\n\n")
    
            # 📄 PAGES INTERNES
            if self.internal_pages:
                f.write("📄 PAGES INTERNES\n")
                f.write("="*80 + "\n")
                for page in sorted(self.internal_pages)[:100]:
                    f.write(f"  🔗 {page}\n")
                if len(self.internal_pages) > 100:
                    f.write(f"  ... et {len(self.internal_pages) - 100} autres\n")
                f.write("\n")
            else:
                f.write("📄 PAGES INTERNES\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucune page interne découverte\n\n")
    
            # 📎 FICHIERS INTÉRESSANTS
            if self.interesting_files:
                f.write("📎 FICHIERS INTÉRESSANTS\n")
                f.write("="*80 + "\n")
                for file in sorted(self.interesting_files):
                    f.write(f"  📄 {file}\n")
                f.write("\n")
            else:
                f.write("📎 FICHIERS INTÉRESSANTS\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucun fichier intéressant découvert\n\n")
    
            # 🌍 URLS EXTERNES
            if self.external_urls:
                f.write("🌍 URLS EXTERNES\n")
                f.write("="*80 + "\n")
                for url in sorted(self.external_urls)[:50]:
                    f.write(f"  🌐 {url}\n")
                if len(self.external_urls) > 50:
                    f.write(f"  ... et {len(self.external_urls) - 50} autres\n")
                f.write("\n")
            else:
                f.write("🌍 URLS EXTERNES\n")
                f.write("="*80 + "\n")
                f.write("✅ Aucune URL externe découverte\n\n")
    
            # 📊 RÉSUMÉ FINAL
            f.write("📊 RÉSUMÉ FINAL\n")
            f.write("="*80 + "\n")
            total_urls_in_files = sum(len(urls) for urls in self.urls_from_files.values())
            f.write(f"✓ Total URLs visitées: {len(self.visited_urls)}\n")
            f.write(f"📄 Pages internes: {len(self.internal_pages)}\n")
            f.write(f"📎 Fichiers intéressants: {len(self.interesting_files)}\n")
            f.write(f"🎯 Juicy Targets: {len(self.juicy_targets)}\n")
            f.write(f"🔐 Secrets détectés: {len(self.secrets_found)}\n")
            f.write(f"🛠️  Technologies: {len(self.technologies)}\n")
            f.write(f"🌍 URLs externes: {len(self.external_urls)}\n")
            f.write(f"🔗 URLs trouvées dans fichiers: {total_urls_in_files}\n")
            f.write(f"📋 Headers personnalisés: {len(self.custom_headers_found) if hasattr(self, 'custom_headers_found') else 0}\n")
            f.write(f"📊 Headers analysés: {len(self.headers_info)}\n")
    
        print(f"\n✅ Rapport TXT exporté dans: {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='🕷️  Web Crawler - Cartographie de site web pour Bug Bounty',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
📚 EXEMPLES D'UTILISATION

🚀 CRAWL BASIQUE:
  python web_crawler.py https://example.com

⚡ AVEC OPTIONS DE PERFORMANCE:
  python web_crawler.py https://example.com -d 2 --rate-limit 30

🔍 AVEC FILTRAGE:
  python web_crawler.py https://example.com --include-pattern "api|admin" --exclude-pattern "cdn|static"

🔒 AVEC SÉCURITÉ:
  python web_crawler.py https://example.com --scan-secrets --capture-headers --detect-tech

👻 MODE STEALTH:
  python web_crawler.py https://example.com --stealth

📚 AVEC WORDLIST (FUZZING):
  python web_crawler.py https://example.com --wordlist common-paths.txt

📏 PROFONDEUR LIMITÉE:
  python web_crawler.py https://example.com --max-depth 3

📄 FICHIER UNIQUE:
  python web_crawler.py https://example.com/assets/app.js --single-file

📊 EXPORT JSON:
  python web_crawler.py https://example.com --format json

📈 COMPARAISON AVEC CRAWL PRÉCÉDENT:
  python web_crawler.py https://example.com --diff previous_crawl.json
        '''
    )

    parser.add_argument('url', help='🌐 URL du site web à cartographier')

    parser.add_argument('-d', '--delay', type=float, default=1,
                        help='⏱️  Délai entre chaque requête en secondes (défaut: 1)')
    parser.add_argument('--rate-limit', type=int,
                        help='⏱️  Nombre maximum de requêtes par minute (ex: 30)')
    parser.add_argument('--max-depth', type=int,
                        help='📏 Profondeur maximale de crawl (ex: 3)')

    parser.add_argument('--include-pattern', type=str,
                        help='✅ Regex pour inclure uniquement certains chemins (ex: "api|admin|config")')
    parser.add_argument('--exclude-pattern', type=str,
                        help='❌ Regex pour exclure certains chemins (ex: "cdn|static|assets")')

    parser.add_argument('--scan-secrets', action='store_true',
                        help='🔐 Recherche les secrets/credentials dans le contenu')
    parser.add_argument('--capture-headers', action='store_true',
                        help='🔒 Capture et analyse les headers HTTP')
    parser.add_argument('--scan-headers-secrets', action='store_true',
                    help='🔐 Recherche les secrets dans les headers HTTP')
    parser.add_argument('--detect-tech', action='store_true',
                        help='🛠️  Détecte les technologies utilisées')

    parser.add_argument('--stealth', action='store_true',
                        help='👻 Mode stealth: rotation automatique des User-Agents')
    parser.add_argument('--user-agent', type=str,
                        help='🤖 User-Agent personnalisé')
    parser.add_argument('--wordlist', type=str,
                        help='📚 Fichier de wordlist pour fuzzing de répertoires')

    parser.add_argument('--resume', action='store_true',
                        help='🔄 Reprendre un crawl interrompu')
    parser.add_argument('--checkpoint', type=str, default='crawler_checkpoint.json',
                        help='💾 Fichier de checkpoint (défaut: crawler_checkpoint.json)')

    parser.add_argument('--single-file', action='store_true',
                        help='📄 Analyser uniquement le fichier spécifié')

    parser.add_argument('-o', '--output', default='rapport_crawl.txt',
                        help='📁 Nom du fichier de sortie (défaut: rapport_crawl.txt)')
    parser.add_argument('--format', dest='format_output', choices=['txt', 'json'], default='txt',
                        help='📊 Format de sortie: txt ou json (défaut: txt)')
    parser.add_argument('--diff', type=str,
                        help='📈 Comparer avec un crawl précédent (fichier JSON)')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='📢 Mode verbeux')

    parser.add_argument('--proxy', type=str,
                        help='🔌 Proxy HTTP à utiliser (ex: http://127.0.0.1:8080)')

    parser.add_argument('--cookies', type=str,
                        help='🍪 Cookies à envoyer (format: "name1=value1; name2=value2")')

    parser.add_argument('--headers', type=str,
                        help='📋 Headers HTTP personnalisés (format: "Header1: value1; Header2: value2")')

    args = parser.parse_args()

    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║                  🕷️  WEB CRAWLER - BUG BOUNTY 🎯                           ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")
    print()
    print("⚙️  CONFIGURATION:")
    print(f"  🌐 URL cible           : {args.url}")
    print(f"  ⏱️  Délai               : {args.delay}s")
    print(f"  📁 Fichier de sortie   : {args.output}")
    print(f"  📊 Format              : {args.format_output.upper()}")
    print()

    if args.max_depth:
        print(f"  📏 Profondeur max      : {args.max_depth}")
    if args.include_pattern:
        print(f"  ✅ Filtre inclusion    : {args.include_pattern}")
    if args.exclude_pattern:
        print(f"  ❌ Filtre exclusion    : {args.exclude_pattern}")
    if args.rate_limit:
        print(f"  ⏱️  Rate limit          : {args.rate_limit} req/min")
    if args.user_agent:
        print(f"  🤖 User-Agent custom   : Oui")
    if args.stealth:
        print(f"  👻 Mode stealth        : Activé")
    if args.proxy:
        print(f"  🔌 Proxy               : {args.proxy}")
    if args.cookies:
        print(f"  🍪 Cookies             : {len(args.cookies.split(';'))} cookie(s)")
    if args.headers:
        print(f"  📋 Headers custom      : {len(args.headers.split(';'))} header(s)")
    if args.wordlist:
        print(f"  📚 Wordlist            : {args.wordlist}")
    if args.scan_secrets:
        print(f"  🔐 Scan secrets        : Activé")
    if args.capture_headers:
        print(f"  🔒 Analyse headers     : Activée")
    if args.scan_headers_secrets:
        print(f"  🔐 Scan headers secrets: Activé")
    if args.detect_tech:
        print(f"  🛠️  Détection tech      : Activée")
    if args.single_file:
        print(f"  📄 Mode                : Fichier unique")
    if args.resume:
        print(f"  🔄 Reprise             : Oui ({args.checkpoint})")
    if args.diff:
        print(f"  📈 Comparaison         : {args.diff}")

    print()
    print("📢 Verbeux              :", "✅ Oui" if args.verbose else "❌ Non")
    print()
    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print()

    try:
        crawler = WebSiteCrawler(
            args.url,
            delay=args.delay,
            verbose=args.verbose,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
            checkpoint_file=args.checkpoint,
            single_file=args.single_file,
            max_depth=args.max_depth,
            include_pattern=args.include_pattern,
            exclude_pattern=args.exclude_pattern,
            scan_secrets=args.scan_secrets,
            analyze_headers=args.capture_headers,
            stealth=args.stealth,
            wordlist=args.wordlist,
            detect_tech=args.detect_tech,
            proxy=args.proxy,
            format_output=args.format_output,
            cookies=args.cookies,
            custom_headers=args.headers,
            scan_custom_headers_flag=args.scan_headers_secrets
        )

        print("🚀 Démarrage du crawl...\n")
        crawler.start(resume=args.resume and not args.single_file, diff_file=args.diff)
        crawler.export_to_file(args.output)

        print()
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                  ✅ CRAWL TERMINÉ AVEC SUCCÈS! 🎉                          ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        print()
        print(f"📋 Consultez le rapport : {args.output}")
        print()

        if os.path.exists(args.checkpoint) and not args.single_file:
            os.remove(args.checkpoint)
            print(f"🗑️  Checkpoint supprimé")

        print()
        print("✨ Merci d'avoir utilisé Web Crawler! 🕷️")
        print()

    except KeyboardInterrupt:
        print()
        print("⏸️  Interrompu par l'utilisateur")
        print()

    except Exception as e:
        print()
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                    ❌ ERREUR LORS DU CRAWL ❌                              ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        print()
        print(f"❌ Erreur: {e}")
        if args.verbose:
            import traceback
            print()
            traceback.print_exc()
        sys.exit(1)

