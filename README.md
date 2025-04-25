# Tooling

# 🔐 CertScore — Monitoring SSL/TLS

Ce projet permet de détecter et visualiser les certificats SSL/TLS potentiellement suspects en temps réel via une interface web interactive.

## Description

Ce script analyse en temps réel les **certificats SSL/TLS** des **domaines similaires** à un domaine de base pour détecter des risques de **phishing**. Il évalue les certificats sur la **similarité des domaines**, l’**autorité de certification** (**CA**) et la **réputation des adresses IP** via **[AbuseIPDB](https://www.abuseipdb.com)**. Nous utilisons **[CertStream](https://certstream.org)**, on récupère les **[logs de Certificate Transparency (CT)](https://certificate.transparency.dev)** et surveillons l'émission des certificats, identifions les menaces et évaluons la fiabilité des **domaines voisins** en temps réel.

# ⚙️ Étapes d'utilisation

* **Clonez le dépôt Git** :
  ```bash
  git clone https://github.com/NizarBerrada/Tooling.git
  ```
* **Installez les dépendances** :
  Installez toutes les bibliothèques nécessaires en exécutant la commande suivante dans l'environnement virtuel activé :
  ```bash
  pip install -r requirements.txt
  ```
* **Configurez la clé API d'AbuseIPDB** :
  - Suivez la procédure mentionnée dans la section **Installation** pour configurer votre clé API.

1. **Démarrer le serveur Flask**

Ouvrez un premier terminal et exécutez la commande suivante :

```bash
python3 server.py --start
```

Le serveur démarre à l’adresse suivante : [http://127.0.0.1:5000](http://127.0.0.1:5000)

2. **Lancez le script** :

Dans un deuxième terminal, démarrez l'analyse des certificats SSL/TLS avec la commande suivante :

```bash
python3 main.py --start
```

3. **Visualisation des résultats** :

   Le script surveillera les certificats SSL/TLS et enregistrera les résultats dans un fichier `suspicious_domains.log`.
4. **Suivre les aletres**

Ouvrez votre navigateur à l’adresse : [http://127.0.0.1:5000](http://127.0.0.1:5000)

Le serveur affichera en temps réel les domaines suspects, leur niveau de confiance, score, et anomalies détectées.

## Fonctionnalités

- Analyse en temps réel des **certificats SSL/TLS** via **CertStream**.
- Détection de la **similarité des domaines** pour repérer le **typosquatting**.
- Évaluation de la **réputation des autorités de certification** et des **adresses IP** via **AbuseIPDB**.
- Génération d'un **score de criticité** basé sur plusieurs critères (**réputation**, **validité**, **similarité**, etc.).
- Enregistrement des **domaines suspects** dans un fichier `suspicious_domains.log`.

## Objectif Global

Évaluer en temps réel le niveau de **criticité** et les **risques** associé à chaque certificat, en se basant sur :

- **Similarité des Domaines** : Détection des risques de **typosquatting**.
- **Réputation de l'Autorité de Certification** : Évaluation de la fiabilité des **autorités de certification**.
- **Réputation des Adresses IP via AbuseIPDB** : Identification des activités **malveillantes**.

## Critères de Scoring

| **Critère**                             | **Description**                                                                      | **Impact sur le Score**                                             |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| **Organisation émettrice**              | Vérifie si l'émetteur est une organisation de confiance.                                 | **+10** (Trusted), **-50** (Blacklistée)                     |
| **Similarité du domaine**               | Mesure de la similarité entre le domaine et un domaine de référence.                    | Similarité élevée : réduction du score en %                           |
| **Validité du certificat**              | Vérifie la durée de validité du certificat.                                             | **>825 jours** : **-10**, **<10 jours** : **-10** |
| **Basic Constraints (CA:TRUE/CA:FALSE)** | Vérifie si le certificat est une autorité de certification.                              | **CA:TRUE** : **+10**, **CA:FALSE** : **-10**     |
| **CRL Distribution Points**              | Vérifie la présence de points de distribution de la liste de révocation des certificats | Présence :**+5**, Absence : **-10**                          |
| **Key Usage (Digital Signature)**        | Vérifie si le certificat permet l’utilisation de la**signature numérique.**       | Présence :**+5**, Absence : **-10**                          |
| **Subject Alternative Names (SANs)**     | Vérifie la présence de**noms alternatifs** dans le certificat (DNS)                | Présence :**+1** par SAN, Absence : **-5**                   |
| **Extended Key Usage (EKUs)**            | Vérifie les usages étendus définis dans le certificat.                                  | Présence :**+5**, Absence : **-5**                           |
| **AbuseIPDB Reputation**                 | Analyse la réputation de l’adresse IP liée au domaine sur**AbuseIPDB**            | Mauvaise réputation : réduction basée sur le score IP                  |

## Procédure d'Installation

### 1. Prérequis

- **Python 3.9+**.
- Bibliothèques Python (installées via `requirements.txt`).
- Une **clé API AbuseIPDB** (pour vérifier la réputation des adresses IP).

### 2. Installation

1. **Clonez le dépôt Git** :

   ```bash
   git clone https://github.com/NizarBerrada/Tooling.git
   ```
2. **Créer et activer un environnement virtuel (optionnel)**
   Il est recommandé d'utiliser un **environnement virtuel** pour isoler les dépendances du projet.

- Sur **Linux/MacOS** :

  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```
- Sur **Windows** :

  ```bash
  python3 -m venv venv
  venv\Scripts\activate
  ```

### 3. Installer les dépendances

Installez toutes les bibliothèques nécessaires en exécutant la commande suivante dans l'environnement virtuel activé :

```bash
pip install -r requirements.txt
```

### 4. Configurer la clé API d'AbuseIPDB

Le script nécessite une clé API d'AbuseIPDB pour vérifier la réputation des adresses IP. Suivez ces étapes :

1. Créez un compte sur [AbuseIPDB](https://www.abuseipdb.com/).
2. Obtenez votre **clé API**.
3. Définissez votre clé API dans la variable d'environnement **ABUSEIPDB_API_KEY** :

   - Sur **Linux/MacOS** :
     ```bash
     export API_KEY=<votre_clé_api>
     ```
   - Sur **Windows** :
     ```bash
     set API_KEY=<votre_clé_api>
     ```

   Copiez **.env.example** en **.env** et renseignez vos clés API. Vous pouvez également créer un fichier `.env` à la racine du projet et y ajouter la ligne suivante.

   API_KEY=<votre_clé_api>

### 5. Vérification de la configuration

Assurez-vous que la configuration est correcte en exécutant la commande suivante :

```bash
python3 main.py --test
```

Cela vérifiera que toutes les dépendances sont correctement installées et que la clé API fonctionne correctement.

### 6. Lancer l'analyse

Une fois la configuration terminée, vous pouvez démarrer l'analyse en temps réel des certificats SSL/TLS avec la commande suivante :

```bash
python3 main.py --start
```

Le script commencera à surveiller les certificats SSL/TLS et à enregistrer les résultats dans un fichier `suspicious_domains.log`.

### Guide de configuration

##### 1. Définir le domaine de base

Le script utilise un fichier de configuration `config.py` où vous pouvez définir votre **domaine de base** et personnaliser le fichier des mots-clés. Par défaut, le domaine de base est configuré comme `pepito.com`.

Pour utiliser votre propre domaine, modifiez la variable `BASE_DOMAIN` dans le fichier `config.py` :

```python
BASE_DOMAIN = "votre-domaine.com"
```

##### 2. Fchier `keywords.json`

Le fichier **keywords.json** contient une liste de domaines similaires au vôtre, avec un score de similarité.

##### Configurer le chemin dans `config.py`

Indiquez le chemin du fichier `keywords.json`:

```env
KEYWORDS_FILE= "./<chemin>/keywords.json"
```

Vous pouvez créer ce fichier manuellement, ou le générer automatiquement avec la commande:

```bash
python3 main.py --typosquats
```

La fonction **generate_typosquats()** produit le fichier `keywords.json`, contenant des variations (typosquats) du domaine de base, et calcule leurs scores avec la distance de **Levenshtein** pour évaluer leur similarité.

#### Options de ligne de commande

Voici les options de ligne de commande disponibles :

- `--start` : Démarre l'analyse en temps réel des **certificats SSL/TLS**.
- `--test` : Effectue un test pour vérifier la configuration sans analyser les certificats.
- `--typosquats` :  Génère un fichier contenant des variantes typographiques (domaines frauduleux potentiels) avec leurs scores de similarité au domaine de base.

### Désinstallation

Si vous souhaitez supprimer le projet et son environnement:

1. Désactivez l'environnement virtuel :

   ```bash
   deactivate
   ```
2. Supprimez le dossier du projet :

   ```bash
   rm -rf <nom-du-dépôt>
   ```
