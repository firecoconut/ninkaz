# 🕷️ Ninkaz Web Crawler | By BlueB1rd

Un outil puissant et complet pour cartographier les sites web et découvrir des vulnérabilités lors de vos tests de sécurité (bug bounty).

## ✨ Fonctionnalités

### 🔍 Crawling & Reconnaissance
- ✅ Crawl récursif des pages web
- ✅ Extraction automatique des URLs internes et externes
- ✅ Détection des répertoires et fichiers intéressants
- ✅ Support des fichiers JavaScript, JSON, XML, etc.
- ✅ Extraction d'URLs depuis le contenu des fichiers

### 🔐 Sécurité & Secrets
- 🔑 Détection automatique des secrets (API keys, tokens, passwords)
- 🔐 Scan de credentials en dur dans le code
- 📊 Classification par sévérité (CRITICAL, HIGH, MEDIUM)
- 🎯 Identification des "juicy targets" (endpoints sensibles)

### 🛠️ Analyse Avancée
- 🔧 Détection des technologies utilisées (frameworks, CMS, etc.)
- 🔒 Analyse des headers de sécurité HTTP
- 📈 Fuzzing de répertoires avec wordlist
- 👻 Mode stealth avec rotation User-Agent
- 🔌 Support des proxies HTTP

### 💾 Gestion d'État
- 📂 Sauvegarde automatique des checkpoints
- 🔄 Reprise de crawl interrompu
- 📊 Export en TXT et JSON
- 📈 Comparaison avec crawl précédent

---

## 🚀 Installation

### Prérequis
- Python 3.7+
- pip

### Dépendances
```bash
pip install requests beautifulsoup4
```

### Téléchargement
```bash
git clone https://github.com/votre-repo/web-crawler.git
cd web-crawler
```

---

## 📖 Utilisation

### Crawl Basique
```bash
python3 ninka.py https://example.com
```

### Avec Options de Performance
```bash
python3 ninka.py https://example.com -d 2 --rate-limit 30
```

### Avec Scan de Secrets
```bash
python3 ninka.py https://example.com --scan-secrets --capture-headers --detect-tech
```

### Mode Stealth (Rotation User-Agent)
```bash
python3 ninka.py https://example.com --stealth
```

### Avec Wordlist (Fuzzing)
```bash
python3 ninka.py https://example.com --wordlist common-paths.txt
```

### Profondeur Limitée
```bash
python3 ninka.py https://example.com --max-depth 3
```

### Fichier Unique
```bash
python3 ninka.py https://example.com/assets/app.js --single-file
```

### Export JSON
```bash
python3 ninka.py https://example.com --format json
```

### Comparaison avec Crawl Précédent
```bash
python3 ninka.py https://example.com --diff previous_crawl.json
```

### Reprise d'un Crawl Interrompu
```bash
python3 ninka.py https://example.com --resume
```

---

## 🎯 Options Complètes

```
usage: ninka.py [-h] [-d DELAY] [--rate-limit RATE_LIMIT] [--max-depth MAX_DEPTH]
                 [--include-pattern INCLUDE_PATTERN] [--exclude-pattern EXCLUDE_PATTERN]
                 [--scan-secrets] [--capture-headers] [--detect-tech]
                 [--stealth] [--user-agent USER_AGENT] [--wordlist WORDLIST]
                 [--resume] [--checkpoint CHECKPOINT] [--single-file]
                 [-o OUTPUT] [--format {txt,json}] [--diff DIFF]
                 [-v] [--proxy PROXY]
                 url

Positional Arguments:
  url                           🌐 URL du site web à cartographier

Optional Arguments:
  -h, --help                    Affiche l'aide
  -d, --delay DELAY             ⏱️  Délai entre requêtes en secondes (défaut: 1)
  --rate-limit RATE_LIMIT       ⏱️  Nombre max de requêtes/minute (ex: 30)
  --max-depth MAX_DEPTH         📏 Profondeur maximale de crawl (ex: 3)
  --include-pattern PATTERN     ✅ Regex pour inclure certains chemins
  --exclude-pattern PATTERN     ❌ Regex pour exclure certains chemins
  --scan-secrets                🔐 Recherche les secrets/credentials
  --capture-headers             🔒 Capture et analyse les headers HTTP
  --detect-tech                 🛠️  Détecte les technologies utilisées
  --stealth                     👻 Mode stealth (rotation User-Agent)
  --user-agent AGENT            🤖 User-Agent personnalisé
  --wordlist FILE               📚 Fichier wordlist pour fuzzing
  --resume                      🔄 Reprendre un crawl interrompu
  --checkpoint FILE             💾 Fichier de checkpoint (défaut: crawler_checkpoint.json)
  --single-file                 📄 Analyser uniquement un fichier
  -o, --output FILE             📁 Fichier de sortie (défaut: rapport_crawl.txt)
  --format {txt,json}           📊 Format de sortie (défaut: txt)
  --diff FILE                   📈 Comparer avec crawl précédent
  -v, --verbose                 📢 Mode verbeux
  --proxy PROXY                 🔌 Proxy HTTP (ex: http://127.0.0.1:8080)
```

---

## 📊 Exemples Pratiques

### 1️⃣ Reconnaissance Complète
```bash
python3 ninka.py https://target.com \
  --scan-secrets \
  --capture-headers \
  --detect-tech \
  --max-depth 2 \
  -o rapport_complet.txt
```

### 2️⃣ Fuzzing de Répertoires
```bash
python3 ninka.py https://target.com \
  --wordlist /path/to/wordlist.txt \
  --rate-limit 30 \
  --stealth
```

### 3️⃣ Analyse d'une API
```bash
python3 ninka.py https://target.com/api/v1 \
  --include-pattern "api|v[0-9]" \
  --scan-secrets \
  --format json
```

### 4️⃣ Analyse d'un Fichier JavaScript
```bash
python3 ninka.py https://target.com/assets/app.js \
  --single-file \
  --scan-secrets \
  --detect-tech
```

### 5️⃣ Mode Stealth avec Proxy
```bash
python3 ninka.py https://target.com \
  --stealth \
  --proxy http://127.0.0.1:8080 \
  --delay 3 \
  --rate-limit 20
```

---

## 📋 Rapport de Sortie

Le rapport généré contient :

### 📊 Statistiques Globales
- Total URLs visitées
- Pages internes découvertes
- Fichiers intéressants
- Juicy targets
- Secrets détectés
- Technologies identifiées

### 🔐 Secrets Détectés
- **CRITICAL** : AWS Keys, Private Keys, GitHub Tokens
- **HIGH** : API Keys, Passwords, Bearer Tokens
- **MEDIUM** : Autres credentials

### 🎯 Juicy Targets
- Endpoints sensibles (admin, api, config, etc.)
- Fichiers intéressants (.env, .git, .sql, etc.)
- Patterns de sécurité

### 🛠️ Technologies
- Frameworks (React, Angular, Vue, etc.)
- CMS (WordPress, Drupal, Joomla, etc.)
- Serveurs (Apache, Nginx, IIS, etc.)
- Langages (PHP, Python, Node.js, etc.)

### 🔒 Analyse Sécurité
- Headers manquants
- Configurations exposées
- Endpoints non sécurisés

---

## 🔍 Patterns de Détection

### Secrets Détectés
- 🔑 API Keys
- 🔐 AWS Keys (AKIA...)
- 🔑 Private Keys (RSA, DSA, EC)
- 🔑 Bearer Tokens
- 🔑 JWT Tokens
- 🔑 Database URLs
- 🔑 Slack Tokens
- 🔑 GitHub Tokens
- 🔑 Stripe Keys
- 🔑 Firebase Config
- 🔑 Google API Keys
- 🔑 Passwords & Credentials

### Fichiers Intéressants
- `.js`, `.json`, `.xml`, `.txt`
- `.php`, `.asp`, `.aspx`, `.jsp`
- `.env`, `.config`, `.sql`
- `.git`, `.svn`, `.bak`, `.old`
- Archives : `.zip`, `.tar`, `.gz`, `.rar`

---

## ⚙️ Configuration Avancée

### Filtrage par Pattern
```bash
# Inclure uniquement les endpoints API
python3 ninka.py https://target.com --include-pattern "api|v[0-9]"

# Exclure les ressources statiques
python3 ninka.py https://target.com --exclude-pattern "cdn|static|assets"
```

### Rate Limiting
```bash
# 30 requêtes par minute
python3 ninka.py https://target.com --rate-limit 30
```

### Profondeur de Crawl
```bash
# Limiter à 3 niveaux de profondeur
python3 ninka.py https://target.com --max-depth 3
```

---

## 📁 Structure des Fichiers

```
web-crawler/
├── ninka.py                 # Script principal
├── rapport_crawl.txt        # Rapport généré (TXT)
├── rapport_crawl.json       # Rapport généré (JSON)
├── crawler_checkpoint.json  # Checkpoint automatique
├── wordlist.txt             # Wordlist personnalisée
└── README.md                # Cette documentation
```

---

## 💾 Formats de Sortie

### Format TXT
Rapport lisible avec emojis et mise en forme ASCII

### Format JSON
```json
{
  "metadata": {
    "date": "2024-01-15T10:30:00",
    "site": "https://example.com",
    "format_version": "1.0"
  },
  "statistics": {
    "total_urls_visited": 150,
    "secrets_found": 5,
    "technologies": 12
  },
  "secrets": [
    {
      "type": "Password ($scope)",
      "url": "https://example.com/assets/app.js",
      "value": "SmartIndustryDemo!2023",
      "severity": "CRITICAL"
    }
  ],
  "juicy_targets": [...],
  "technologies": [...]
}
```

---

## 🛡️ Bonnes Pratiques

### ✅ À Faire
- ✅ Obtenir une autorisation écrite avant de tester
- ✅ Respecter le `robots.txt` et les conditions d'utilisation
- ✅ Utiliser un délai approprié entre les requêtes
- ✅ Tester sur un environnement de test d'abord
- ✅ Sauvegarder les rapports pour comparaison future

### ❌ À Éviter
- ❌ Crawler sans autorisation
- ❌ Utiliser un délai trop court (DoS)
- ❌ Partager les secrets découverts publiquement
- ❌ Modifier ou supprimer des données
- ❌ Accéder à des données sensibles sans permission

---

## 🐛 Dépannage

### Le crawl est trop lent
```bash
# Réduire le délai
python3 ninka.py https://target.com -d 0.5

# Augmenter le rate limit
python3 ninka.py https://target.com --rate-limit 60
```

### Erreur de connexion
```bash
# Utiliser un proxy
python3 ninka.py https://target.com --proxy http://127.0.0.1:8080

# Augmenter le timeout
# (Modifier timeout=10 dans fetch_page())
```

### Trop de faux positifs
```bash
# Utiliser des patterns de filtrage
python3 ninka.py https://target.com --exclude-pattern "test|demo|example"
```

### Reprendre un crawl
```bash
# Utiliser --resume
python3 ninka.py https://target.com --resume
```

---

## 📊 Cas d'Usage

### 🎯 Bug Bounty
- Reconnaissance initiale du scope
- Découverte d'endpoints cachés
- Identification de secrets exposés
- Détection de technologies vulnérables

### 🔒 Pentest
- Cartographie complète du site
- Identification des points d'entrée
- Analyse des headers de sécurité
- Découverte de fichiers sensibles

### 🛡️ Security Audit
- Vérification de la configuration
- Détection de mauvaises pratiques
- Comparaison avec audits précédents
- Documentation des findings

---

## 📝 Licence

MIT License - Libre d'utilisation

---

## ⚠️ Disclaimer

**Cet outil est fourni à titre éducatif uniquement.**

L'utilisateur est seul responsable de l'utilisation de cet outil. Ne l'utilisez que sur des systèmes pour lesquels vous avez une autorisation explicite. L'utilisation non autorisée est illégale.

---

## 🤝 Contribution

Les contributions sont bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Ajouter de nouveaux patterns
- Améliorer la documentation

---

## 📞 Support

Pour toute question ou problème :
- 📧 Email : support@example.com
- 🐛 Issues : GitHub Issues
- 💬 Discussions : GitHub Discussions

---

## 🎉 Merci d'utiliser Web Crawler !

**Bon crawling et bonne chasse aux vulnérabilités ! 🕷️🎯**
