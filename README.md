# 🛡️ ThreatHarvest

**ThreatHarvest** est un outil de Cyber Threat Intelligence (CTI) SIEM-ready qui collecte, analyse et visualise automatiquement les menaces cyber depuis URLhaus et Feodo Tracker.

## ✨ Fonctionnalités

- 📊 **Collecte automatisée** de données depuis URLhaus et Feodo Tracker
- 🧠 **Analyse IA** via Groq API (modèle llama-3.3-70b-versatile)
- 📈 **Visualisations** : Pie chart (Top 5 familles) + Histogramme (évolution volumétrie)
- 📄 **Rapport HTML** avec mode sombre
- 🔍 **Détection de nouvelles menaces** par comparaison journalière
- 💾 **Données standardisées** (JSON snake_case + timestamps ISO 8601)
- 🎯 **Extraction intelligente** des familles de malware (Mozi, Mirai, etc.)

## 📁 Structure du Projet

```
ThreatHarvester/
├── data/                              # Données JSON standardisées
│   └── threat_feed_YYYY-MM-DD.json   # Feed quotidien
├── output/                            # Rapports par date
│   └── YYYY-MM-DD/                   # Dossier du jour
│       ├── distrib_famille.png       # Pie chart Top 5 familles
│       ├── evolution_volumetrie.png  # Histogramme comparatif
│       └── report_YYYY-MM-DD.html    # Rapport HTML complet
├── requirements.txt                   # Dépendances Python
├── threat_knowledge_base.json         # Cache AI (Groq)
└── threatharvest.py                   # Script principal
```

## 🚀 Installation

### Prérequis
- Python 3.8+
- Clé API Groq (optionnel, pour l'analyse IA)

### Étapes

1. **Cloner le repository**
```bash
git clone <repo-url>
cd ThreatHarvester
```

2. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

3. **Configurer la clé API Groq** (optionnel)
```bash
# Windows
set GROQ_API_KEY=votre_clé_api

# Linux/Mac
export GROQ_API_KEY=votre_clé_api
```

## 📖 Utilisation

### Lancement Simple
```bash
python threatharvest.py
```

### Sortie Console
```
ThreatHarvest Started...
2026-02-10 15:48:11,215 - INFO - Directories initialized: data, output/2026-02-10
2026-02-10 15:48:11,215 - INFO - Fetching URLhaus data...
2026-02-10 15:48:11,575 - INFO - Fetching Feodo Tracker data...

               Top 10 Malwares of the Day
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┓
┃ Rank ┃ Malware / Tag                  ┃ Count ┃ Trend ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━┩
│    1 │ 32-bit,elf,mips,Mozi           │  6754 │   =   │
│    2 │ elf,mirai,ua-wget              │  1658 │   =   │
...

Total IOCs Collected: 19,767
Unique Malware Families: 182

[AI] Strategic Briefing
...

Report available at: output/2026-02-10/report_2026-02-10.html
```

### Fichiers Générés

Chaque exécution crée :
- `data/threat_feed_YYYY-MM-DD.json` - Données brutes standardisées
- `output/YYYY-MM-DD/distrib_famille.png` - Distribution des familles
- `output/YYYY-MM-DD/evolution_volumetrie.png` - Évolution du volume
- `output/YYYY-MM-DD/report_YYYY-MM-DD.html` - Rapport HTML complet

## 📊 Schéma de Données

### Format JSON (SIEM-Ready)
```json
{
    "date": "2026-02-10 14:19:09",
    "ioc_value": "http://42.224.11.192:38078/i",
    "ioc_type": "url",
    "threat_tag": "32-bit,elf,mips,Mozi",
    "source": "URLhaus",
    "collected_at": "2026-02-10T14:27:35Z",
    "malware_family": "Mozi"
}
```

### Champs Standardisés
- `date` : Date de détection (YYYY-MM-DD HH:MM:SS)
- `ioc_value` : Indicateur de compromission (URL, IP:PORT)
- `ioc_type` : Type d'IOC (url, ip:port)
- `threat_tag` : Tag brut de la menace
- `source` : Source de données (URLhaus, FeodoTracker)
- `collected_at` : Timestamp ISO 8601 de collecte
- `malware_family` : Famille extraite (Mozi, Mirai, CoinMiner, etc.)

## 🧠 Analyse IA

### Configuration Groq
L'outil utilise l'API Groq pour enrichir les menaces avec :
- **Famille** : Nom de la famille de malware
- **Description** : Résumé court (max 15 mots)
- **Niveau de risque** : Low, Medium, High, Critical

### Cache Local
Les analyses sont mises en cache dans `threat_knowledge_base.json` pour :
- Réduire les coûts API
- Accélérer les exécutions futures
- Fonctionner hors-ligne pour les menaces connues

### Mode Dégradé
Sans clé API, l'outil fonctionne normalement mais :
- Pas d'enrichissement IA pour les nouvelles menaces
- Utilisation uniquement du cache existant

## 📈 Analyse de Tendances

### Détection de Nouvelles Menaces
Le script compare automatiquement :
- Données du jour vs données de la veille
- Identifie les nouvelles familles de malware
- Calcule les deltas de volume (+/- par menace)

### Indicateurs de Tendance
- `+X ^` : Augmentation du volume
- `-X v` : Diminution du volume
- `New *` : Nouvelle entrée dans le Top 10
- `=` : Pas de changement

## 🎨 Visualisations

### Pie Chart (distrib_famille.png)
- Top 5 des familles de malware
- Pourcentages de distribution
- Style dark mode avec couleurs vibrantes

### Histogram (evolution_volumetrie.png)
- Comparaison Hier vs Aujourd'hui
- Volume total de menaces
- Barres annotées avec valeurs

## 📄 Rapport HTML

Le rapport HTML inclut :
- **Résumé exécutif** : Métriques clés (IOCs, familles, nouvelles menaces)
- **Briefing IA** : Analyse des Top 5 menaces
- **Alertes** : Nouvelles menaces détectées
- **Visualisations** : Graphiques embarqués
- **Top 10** : Tableau des menaces principales

### Accès au Rapport
```bash
# Ouvrir le rapport du jour
start output/2026-02-10/report_2026-02-10.html  # Windows
open output/2026-02-10/report_2026-02-10.html   # Mac
xdg-open output/2026-02-10/report_2026-02-10.html  # Linux
```

## 🔧 Architecture Technique

### Extraction de Familles
Algorithme intelligent qui :
1. Split par virgules (délimiteur principal)
2. Filtre les termes d'architecture (elf, 32-bit, mips, etc.)
3. Priorise les noms capitalisés (Mozi, Mirai)
4. Retourne la famille nettoyée

### Modularité
Fonctions organisées par responsabilité :
- **Fetching** : `fetch_urlhaus()`, `fetch_feodo()`
- **Processing** : `standardize_data()`, `extract_malware_family()`
- **Analysis** : `get_new_entrants()`, `analyze_threat_with_ai()`
- **Visualization** : `generate_pie_chart()`, `generate_histogram()`
- **Reporting** : `generate_console_report()`, `generate_html_report()`

## 🛠️ Dépendances

```
pandas          # Manipulation de données
requests        # Requêtes HTTP
rich            # Interface console
groq            # API Groq pour IA
matplotlib      # Visualisations
```

## 📝 Logs

Les logs sont affichés en temps réel :
- `INFO` : Opérations normales
- `WARNING` : Données vides ou problèmes mineurs
- `ERROR` : Erreurs de fetch, parsing, ou génération

## 🤝 Contribution

Pour contribuer :
1. Fork le projet
2. Créer une branche (`git checkout -b feature/amelioration`)
3. Commit les changements (`git commit -m 'Ajout fonctionnalité'`)
4. Push (`git push origin feature/amelioration`)
5. Ouvrir une Pull Request


## 🔗 Sources de Données

- **URLhaus** : https://urlhaus.abuse.ch/
- **Feodo Tracker** : https://feodotracker.abuse.ch/

---

**Développé par ScratchToSphere pour la communauté CTI**
