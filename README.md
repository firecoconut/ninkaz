# 🕷️ Ninkaz - Web Crawler pour Bug Bounty

Un crawler web puissant et flexible conçu pour la cartographie de sites web et la recherche de vulnérabilités en bug bounty.

## ✨ Fonctionnalités

### 🔍 Exploration Web
- ✅ Crawl récursif avec gestion de la profondeur
- ✅ Extraction automatique d'URLs depuis le contenu HTML/JS
- ✅ Support des répertoires parents et fichiers intéressants
- ✅ Fuzzing de répertoires avec wordlist
- ✅ Gestion des checkpoints pour reprendre un crawl interrompu

### 🔐 Sécurité & Analyse
- ✅ Détection automatique de secrets (API keys, tokens, credentials)
- ✅ Analyse des headers HTTP de sécurité
- ✅ Détection des technologies utilisées (React, Angular, Django, etc.)
- ✅ Identification des "juicy targets" (endpoints sensibles)
- ✅ Scan des patterns sensibles (admin, api, config, etc.)
- ✅ **Détection des headers personnalisés (X-*, Custom-*, App-*, API-*)** 📋
- ✅ **Scan des secrets dans les headers HTTP** 🔐

### 🛠️ Options Avancées
- ✅ Mode stealth avec rotation automatique des User-Agents
- ✅ Support des proxies HTTP
- ✅ **Support des cookies personnalisés** 🍪
- ✅ **Support des headers HTTP personnalisés** 📋
- ✅ Rate limiting configurable
- ✅ Filtrage par regex (inclusion/exclusion)
- ✅ Export en JSON ou TXT
- ✅ Comparaison avec crawls précédents

---

## 📦 Installation

### Prérequis
- Python 3.7+
- pip

### Dépendances
```bash
pip install requests beautifulsoup4
```

### Téléchargement
```bash
git clone https://github.com/[USER]/ninkaz.git
cd ninkaz
```

---

## 🚀 Utilisation

### Crawl Basique
```bash
python ninkaz.py https://example.com
```

### Avec Cookies
```bash
python ninkaz.py https://example.com --cookies "session=abc123; token=xyz789"
```

### Avec Headers Personnalisés
```bash
python ninkaz.py https://example.com --headers "Authorization: Bearer token123; X-Custom: value"
```

### Avec Cookies ET Headers
```bash
python ninkaz.py https://example.com \
  --cookies "session=abc123" \
  --headers "Authorization: Bearer token; X-API-Key: key123"
```

### Mode Stealth + Secrets
```bash
python ninkaz.py https://example.com --stealth --scan-secrets --detect-tech
```

### Avec Wordlist (Fuzzing)
```bash
python ninkaz.py https://example.com --wordlist common-paths.txt
```

### Profondeur Limitée
```bash
python ninkaz.py https://example.com --max-depth 3
```

### Avec Filtrage
```bash
python ninkaz.py https://example.com \
  --include-pattern "api|admin" \
  --exclude-pattern "cdn|static|assets"
```

### Rate Limiting
```bash
python ninkaz.py https://example.com --rate-limit 30
```

### Export JSON
```bash
python ninkaz.py https://example.com --format json -o rapport.json
```

### Reprendre un Crawl Interrompu
```bash
python ninkaz.py https://example.com --resume
```

### Comparaison avec Crawl Précédent
```bash
python ninkaz.py https://example.com --diff previous_crawl.json
```

### Fichier Unique
```bash
python ninkaz.py https://example.com/assets/app.js --single-file --scan-secrets
```

### Scan des Secrets dans les Headers
```bash
python ninkaz.py https://example.com --scan-headers-secrets
```

### Audit Complet
```bash
python ninkaz.py https://example.com \
  --scan-secrets \
  --scan-headers-secrets \
  --capture-headers \
  --detect-tech \
  --stealth \
  -v
```

---

## 📋 Arguments Disponibles

| Argument | Description | Exemple |
|----------|-------------|---------|
| `url` | URL cible à crawler | `https://example.com` |
| `-d, --delay` | Délai entre requêtes (secondes) | `-d 2` |
| `--rate-limit` | Max requêtes/minute | `--rate-limit 30` |
| `--max-depth` | Profondeur maximale | `--max-depth 3` |
| `--include-pattern` | Regex d'inclusion | `--include-pattern "api\|admin"` |
| `--exclude-pattern` | Regex d'exclusion | `--exclude-pattern "cdn\|static"` |
| `--scan-secrets` | Rechercher les secrets | `--scan-secrets` |
| `--scan-headers-secrets` | Rechercher secrets dans headers | `--scan-headers-secrets` |
| `--capture-headers` | Analyser les headers | `--capture-headers` |
| `--detect-tech` | Détecter les technologies | `--detect-tech` |
| `--stealth` | Mode stealth (rotation UA) | `--stealth` |
| `--user-agent` | User-Agent personnalisé | `--user-agent "Mozilla/5.0..."` |
| `--wordlist` | Fichier wordlist | `--wordlist paths.txt` |
| `--resume` | Reprendre un crawl | `--resume` |
| `--checkpoint` | Fichier checkpoint | `--checkpoint state.json` |
| `--single-file` | Analyser un seul fichier | `--single-file` |
| `-o, --output` | Fichier de sortie | `-o rapport.txt` |
| `--format` | Format (txt/json) | `--format json` |
| `--diff` | Comparer avec crawl précédent | `--diff old_crawl.json` |
| `-v, --verbose` | Mode verbeux | `-v` |
| `--proxy` | Proxy HTTP | `--proxy http://127.0.0.1:8080` |
| `--cookies` | Cookies à envoyer | `--cookies "name=value; name2=value2"` |
| `--headers` | Headers personnalisés | `--headers "Header: value; X-Custom: val"` |

---

## 🍪 Format des Cookies

Les cookies doivent être au format `name=value` séparés par des points-virgules :

```bash
--cookies "session_id=abc123; user_token=xyz789; theme=dark"
```

---

## 📋 Format des Headers

Les headers doivent être au format `Header: value` séparés par des points-virgules :

```bash
--headers "Authorization: Bearer token123; X-API-Key: mykey; X-Custom-Header: value"
```

---

## 🔐 Secrets Détectés

Le scanner recherche automatiquement :

### Patterns Génériques
- 📧 Emails
- 🔑 API Keys (tous les formats : `api_key`, `apiKey`, `API_KEY`, etc.)
- 🔐 Tokens (Bearer, JWT, Auth, Access, Refresh)
- 💾 Credentials (username/password)
- 🗄️ Database URLs
- 🔒 Private Keys
- 🔧 Firebase Config
- 🌐 Google API Keys

### Patterns Spécifiques
- 🔑 AWS Keys (`AKIA...`)
- 🎫 Slack Tokens (`xox...`)
- 🐙 GitHub Tokens (`ghp_...`)
- 💳 Stripe Keys (`sk_live_...`, `sk_test_...`)

### Headers Personnalisés
- 📋 `X-API-Key`
- 📋 `X-APP-ID`
- 📋 `X-Token`
- 📋 `X-Access-Token`
- 📋 `X-Auth-Token`
- 📋 `X-Custom-Auth`
- 📋 `Authorization`
- 📋 Tous les headers `X-*` personnalisés

---

## 🛠️ Technologies Détectées

React, Angular, Vue.js, jQuery, Bootstrap, WordPress, Drupal, Joomla, Django, Flask, Laravel, Node.js, Express, ASP.NET, Java, et plus...

---

## 📊 Résultats

### Rapport TXT
Le rapport inclut :
- 📊 Statistiques globales
- 🎯 Cibles prometteuses (juicy targets)
- 🔐 Secrets détectés
- 📋 Headers personnalisés détectés
- 🛠️ Technologies identifiées
- 📄 Pages internes
- 📎 Fichiers intéressants
- 🌍 URLs externes

### Rapport JSON
Structure complète avec :
- Métadonnées
- Statistiques
- Listes détaillées
- Headers analysés
- Headers personnalisés trouvés

---

## 📈 Exemples Complets

### Audit Complet d'un Site
```bash
python ninkaz.py https://example.com \
  --stealth \
  --scan-secrets \
  --scan-headers-secrets \
  --capture-headers \
  --detect-tech \
  --rate-limit 30 \
  --format json \
  -o audit_complet.json \
  -v
```

### Crawl avec Authentification
```bash
python ninkaz.py https://example.com \
  --cookies "session=abc123; auth_token=xyz" \
  --headers "Authorization: Bearer mytoken; X-API-Key: key123" \
  --scan-secrets \
  --scan-headers-secrets \
  -o authenticated_crawl.txt
```

### Fuzzing + Secrets
```bash
python ninkaz.py https://example.com \
  --wordlist common-paths.txt \
  --scan-secrets \
  --scan-headers-secrets \
  --max-depth 2 \
  -d 1
```

### Comparaison de Deux Crawls
```bash
# Premier crawl
python ninkaz.py https://example.com -o crawl1.json --format json

# Deuxième crawl (après modifications)
python ninkaz.py https://example.com --diff crawl1.json -o crawl2.json --format json
```

### Détection des Headers Personnalisés
```bash
python ninkaz.py https://example.com \
  --scan-headers-secrets \
  --capture-headers \
  -v
```

Affichera :
```
📋 HEADER CUSTOM DÉTECTÉ: X-Custom-Header: my-value
📋 HEADER CUSTOM DÉTECTÉ: X-Request-ID: 12345
📋 HEADER CUSTOM DÉTECTÉ: App-Version: 1.2.3
🔐 SECRET DÉTECTÉ (Header: Authorization): Bearer eyJ0eXAi...
🔐 SECRET DÉTECTÉ (Header: X-API-Key): Qae-fgh654...
```

---

## 💾 Checkpoints

Les checkpoints permettent de reprendre un crawl interrompu :

```bash
# Démarrer un crawl
python ninkaz.py https://example.com

# (Ctrl+C pour interrompre)

# Reprendre plus tard
python ninkaz.py https://example.com --resume
```

Le fichier `crawler_checkpoint.json` est créé automatiquement.

---

## ⚙️ Configuration Recommandée

### Pour un Crawl Rapide
```bash
python ninkaz.py https://example.com -d 0.5 --rate-limit 60
```

### Pour un Crawl Discret
```bash
python ninkaz.py https://example.com --stealth -d 3 --rate-limit 20
```

### Pour un Audit Complet
```bash
python ninkaz.py https://example.com \
  --stealth \
  --scan-secrets \
  --scan-headers-secrets \
  --capture-headers \
  --detect-tech \
  --wordlist wordlist.txt \
  --max-depth 4 \
  -d 2 \
  --rate-limit 30 \
  -v
```

### Pour une Reconnaissance Rapide
```bash
python ninkaz.py https://example.com \
  --scan-secrets \
  --scan-headers-secrets \
  --detect-tech \
  --max-depth 2 \
  -d 0.5
```

---

## 🐛 Dépannage

### Timeout
Augmentez le délai :
```bash
python ninkaz.py https://example.com -d 3
```

### Trop de requêtes bloquées
Activez le mode stealth :
```bash
python ninkaz.py https://example.com --stealth --rate-limit 20
```

### Besoin d'authentification
Utilisez les cookies et headers :
```bash
python ninkaz.py https://example.com \
  --cookies "session=value" \
  --headers "Authorization: Bearer token"
```

### Erreurs d'indentation
Assurez-vous que le fichier est en UTF-8 :
```bash
python3 -m py_compile ninkaz.py
```

### Pas de secrets détectés
Assurez-vous d'utiliser `--scan-secrets` et `--scan-headers-secrets` :
```bash
python ninkaz.py https://example.com --scan-secrets --scan-headers-secrets -v
```

---

## 📝 Licence

MIT License - Libre d'utilisation

---

## ⚠️ Avertissement Légal

Cet outil est destiné à être utilisé **uniquement sur des sites dont vous avez l'autorisation**. 

L'utilisation non autorisée peut être illégale. Respectez toujours les lois locales et les conditions d'utilisation des sites.

---

## 🤝 Contribution

Les contributions sont bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Soumettre des pull requests

---

## 📞 Support

Pour toute question ou problème, consultez la documentation ou ouvrez une issue.

---

## 🎯 Cas d'Usage

### Reconnaissance (Recon)
```bash
python ninkaz.py https://target.com --detect-tech --max-depth 2 -d 0.5
```

### Recherche de Secrets
```bash
python ninkaz.py https://target.com --scan-secrets --scan-headers-secrets -v
```

### Cartographie Complète
```bash
python ninkaz.py https://target.com \
  --stealth \
  --scan-secrets \
  --scan-headers-secrets \
  --capture-headers \
  --detect-tech \
  --wordlist paths.txt \
  --format json
```

### Suivi des Changements
```bash
# Crawl initial
python ninkaz.py https://target.com -o baseline.json --format json

# Crawl ultérieur
python ninkaz.py https://target.com --diff baseline.json -o current.json --format json
```

---

## 📊 Sortie Exemple

```
🕷️  WEB CRAWLER - BUG BOUNTY 🎯

⚙️  CONFIGURATION:
  🌐 URL cible           : https://example.com
  ⏱️  Délai               : 1s
  📁 Fichier de sortie   : rapport_crawl.txt
  📊 Format              : TXT
  🔐 Scan secrets        : Activé
  🔐 Scan headers secrets: Activé
  🔒 Analyse headers     : Activée
  🛠️  Détection tech      : Activée

🚀 Démarrage du crawl...

🕷️  Exploration [1 / 50] (profondeur: 0): https://example.com
  🔗 15 URL(s) trouvée(s)
  ⚙️  React détecté
  📋 HEADER CUSTOM DÉTECTÉ: X-Custom-Header: value
  🔐 SECRET DÉTECTÉ (Header: Authorization): Bearer eyJ0eXAi...

...

📋 RAPPORT DE CARTOGRAPHIE WEB
════════════════════════════════════════════════════════════════════════════

📊 STATISTIQUES
  ✓ URLs visitées: 45
  📄 Pages internes: 38
  📎 Fichiers intéressants: 7
  🎯 Cibles juteuses: 12
  🔐 Secrets trouvés: 3
  🛠️  Technologies: 5
  🌍 URLs externes: 8

🔐 SECRETS TROUVÉS
  🔑 API Key (camelCase): https://example.com/config.js
     💾 Valeur: Qae-fgh65421345asd61dfg-fgh-5487
  🔑 Header: X-API-Key: https://example.com
     💾 Valeur: 0ok3ed-8521da-klop23

📋 HEADERS PERSONNALISÉS DÉTECTÉS
  📌 X-Custom-Header:
     🌐 https://example.com
     💾 Valeur: my-value
  📌 X-Request-ID:
     🌐 https://example.com/api/users
     💾 Valeur: 12345

✅ CRAWL TERMINÉ AVEC SUCCÈS! 🎉
```

---

**Créé avec ❤️ pour la communauté Bug Bounty**

🕷️ **Ninkaz** - Web Crawler pour Bug Bounty
```
