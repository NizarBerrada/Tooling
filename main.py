# -------- CONFIGURATIONS --------
from collections import defaultdict
from Logger import Logger 
import asyncio
import certstream
import Levenshtein
import json
import os
import Levenshtein
from Levenshtein import ratio
import logging
import re
from dotenv import load_dotenv
from typing import Dict, List, Tuple, Optional, Union
from AbuseIPDBClient import AbuseIPDBClient
import ssl
import socket
import sys
import argparse
from tqdm import tqdm
from datetime import datetime
import time
from config import BASE_DOMAIN, API_KEY, KEYWORDS_FILE, LOGFILE, TRUSTED_ORGS, BLACKLISTED_ORGS
from global_vars import keywords, known_issuers, cert_infos, processed_domains, matched_issuers, analysis_result, abuse_client
from db import init_db, save_alert
# -------- LOGGING SETUP --------
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cert_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)



# -------- UTILITY FUNCTIONS --------
def load_keywords(path):
        with open(path, "r") as f:
            return json.load(f)


def extract_common_name(issuer: str) -> str:
    if not issuer:
        return "Unknown"
    
    org_match = re.search(r"organizationName=([^/]+)", issuer)
    if org_match:
        return org_match.group(1)
    
    cn_match = re.search(r"CN=([^/]+)", issuer)
    if cn_match:
        return cn_match.group(1)
    
    return "Unknown"

def normalize_name(name: str) -> str:
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r"[^a-z0-9]", "", name)
    return name

def is_trusted_org(org: str) -> bool:
    norm_org = normalize_name(org)
    return any(norm_org == normalize_name(trusted) for trusted in TRUSTED_ORGS)

def is_blacklisted_org(org: str) -> bool:
    norm_org = normalize_name(org)
    return any(norm_org == normalize_name(blacklisted) for blacklisted in BLACKLISTED_ORGS)

def get_certificate_info(domains):
    if isinstance(domains, str):
        domains = [domains]  

    results = []
    progress_bar = tqdm(total=len(domains), desc="Scanning Domains", unit="domain")

    for domain in domains:
        cert_info = {
            "domain": domain,
            "issuer": "Unknown Authority",
            "subject": "",
            "san": [],
            "valid_from": "",
            "valid_to": "",
            "serial_number": "",
            "version": "",
            "ocsp": [],
            "ca_issuers": [],
            "crl_distribution_points": [],
            "error": None
        }

        try:
            context = ssl.create_default_context()
            context.timeout = 30 #THRESHOLD

            with socket.create_connection((domain, 443), timeout=30) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Parse issuer
                    if "issuer" in cert:
                        cert_info["issuer"] = "/" + "/".join(
                            f"{item[0]}={item[1]}" for part in cert["issuer"] for item in part
                        )

                    # Parse subject
                    if "subject" in cert:
                        cert_info["subject"] = "/" + "/".join(
                            f"{item[0]}={item[1]}" for part in cert["subject"] for item in part
                        )

                    # Parse SAN
                    if "subjectAltName" in cert:
                        cert_info["san"] = [name[1] for name in cert["subjectAltName"]
                                            if name[0].lower() == "dns"]

                    # Validity
                    if "notBefore" in cert:
                        cert_info["valid_from"] = cert["notBefore"]
                    if "notAfter" in cert:
                        cert_info["valid_to"] = cert["notAfter"]

                    # Serial Number and Version
                    cert_info["serial_number"] = cert.get("serialNumber", "")
                    cert_info["version"] = f"v{cert.get('version', '') + 1}"  # Convert 2 → v3

                    # OCSP, CA Issuers, CRL
                    cert_info["ocsp"] = list(cert.get("OCSP", []))
                    cert_info["ca_issuers"] = list(cert.get("caIssuers", []))
                    cert_info["crl_distribution_points"] = list(cert.get("crlDistributionPoints", []))

        except ssl.SSLError as e:
            cert_info["error"] = f"SSL Error: {str(e)}"
        except socket.timeout:
            cert_info["error"] = "Connection timeout"
        except Exception as e:
            cert_info["error"] = f"Error retrieving certificate: {str(e)}"

        results.append(cert_info)
        progress_bar.update(1)
        
    progress_bar.close()
    return results


# -------- CALLBACKS --------
def my_callback(message, context):
    if message['message_type'] == "heartbeat":
        return
    keywords = load_keywords(KEYWORDS_FILE)
    domains = list(keywords.keys())

    if message['message_type'] == "certificate_update":
        data = message['data']
        leaf_cert = data['leaf_cert']
        extensions = leaf_cert.get('extensions', {})
        subject = leaf_cert.get('subject', {})
        issuer = leaf_cert.get('issuer', {})
         # Extract individual fields
        cert_index = data.get('cert_index')
        cert_link = data.get('cert_link')
        all_domains = leaf_cert.get('all_domains', [])
        authority_info_access = extensions.get('authorityInfoAccess')
        authority_key_identifier = extensions.get('authorityKeyIdentifier')
        basic_constraints = extensions.get('basicConstraints')
        key_usage = extensions.get('keyUsage')
        extended_key_usage = extensions.get('extendedKeyUsage')
        subject_alt_name = extensions.get('subjectAltName')
        subject_key_identifier = extensions.get('subjectKeyIdentifier')
        fingerprint = leaf_cert.get('fingerprint')
        sha1 = leaf_cert.get('sha1')
        sha256 = leaf_cert.get('sha256')
        not_after = leaf_cert.get('not_after')
        not_before = leaf_cert.get('not_before')
        serial_number = leaf_cert.get('serial_number')
        signature_algorithm = leaf_cert.get('signature_algorithm')
        subject_aggregated = subject.get('aggregated')
        subject_cn = subject.get('CN')
        issuer_aggregated = issuer.get('aggregated')
        issuer_cn = issuer.get('CN')
        issuer_o = issuer.get('O')
        issuer_c = issuer.get('C')
        is_ca = leaf_cert.get('is_ca')
        seen = data.get('seen')
        source_name = data.get('source', {}).get('name')
        source_url = data.get('source', {}).get('url')
        update_type = data.get('update_type')
        message_type = message.get('message_type')
    
    norm_issuer = normalize_name(issuer_o)
# --- Prepare Analysis ( based on Authority)---
    if norm_issuer in known_issuers and norm_issuer not in matched_issuers: 
        print(f"[MATCH] Found known issuer: {issuer_o}")
        matched_issuers.add(norm_issuer)
# --- Setting Analysis ---
        for cert in cert_infos:
            if extract_common_name(cert['issuer']) == (issuer_o):
                domain = cert['domain']
                if domain not in processed_domains:
                    processed_domains.add(domain) 
                    analysis_result[domain] = {
                        "trusted": False,
                        "score": 0,
                        "reason": [],
                        "issues": [],
                        "warnings": [],
                        "recommendations": [],
                        "info": ""
                    }
# --- AbuseIPDB Analysis ---
                    abuse_client= AbuseIPDBClient(API_KEY)
                    abuse_data = abuse_client.check_reputation(abuse_client, domain=domain)
                    if abuse_data['score'] > 0:
                            analysis_result[domain]['score'] -= abuse_data['score']
                            analysis_result[domain]['issues'].append(f"⚠️ AbuseIPDB score: {abuse_data['score']}")
# --- Similarity Analysis ---
                    levenshtein_sim = Levenshtein.ratio(BASE_DOMAIN, domain)
                    jaro_sim = Levenshtein.jaro(BASE_DOMAIN, domain)
                    jaro_winkler_sim = Levenshtein.jaro_winkler(BASE_DOMAIN, domain)
                    avg_similarity = (levenshtein_sim + jaro_sim + jaro_winkler_sim) / 3
                    similarity_score = round(avg_similarity * 100)
                    analysis_result[domain]["score"] = -similarity_score
                    analysis_result[domain]["issues"].append(f"⚠️ Similarity score: {similarity_score}%")
# --- Authority Analysis --- 
                if not issuer_o:
                    analysis_result[org]["issues"].append("No organization name found in certificate")
                if is_trusted_org(issuer_o):
                    analysis_result[domain]["trusted"] = True
                    analysis_result[domain]["score"] += 10
                    analysis_result[domain]["reason"].append(f"Trusted organization (whitelist)")
                elif is_blacklisted_org(issuer_o):
                    analysis_result[domain]["trusted"] = False
                    analysis_result[domain]["score"] -= 50
                    analysis_result[domain]["reason"].append(f"Untrusted organization (blacklist)")
                    analysis_result[domain]["issues"].append("⚠️ Organization is blacklisted")
                #else:
                #    analysis_result[domain]["reason"] = "Unknown organization (not in whitelist or blacklist)"
                #    analysis_result[domain]["warnings"].append("Unknown certificate authority")   
# --- Validity Analysis ---

                start_date_str=cert['valid_from']
                end_date_str=cert['valid_to']
                date_format = "%b %d %H:%M:%S %Y GMT"

                start_date = datetime.strptime(start_date_str, date_format)
                end_date = datetime.strptime(end_date_str, date_format)

                if start_date and end_date:
                    duration_days = (end_date - start_date).days
                    if duration_days > 398:
                        analysis_result[domain]["issues"].append("⏱ Validité trop longue (>825 jours)")
                        analysis_result[domain]["score"] -= 10
                    elif duration_days < 10:
                        analysis_result[domain]["issues"].append("⏱ Certificat très court (peut être un test ou éphémère)")
                        analysis_result[domain]["score"] -= 10
                    else:
                        analysis_result[domain]["info"] = (f"📆 Durée du certificat = {duration_days} jours")
# ---Exentensions Analysis ---
# 1. Basic constraint  ---
                if basic_constraints == "CA:TRUE":
                        analysis_result[domain]["issues"].append(f"✅ Le certificat est une autorité de certification (CA:TRUE)")
                        analysis_result[domain]["score"] += 10
                elif "pathlen:0" in basic_constraints:
                        analysis_result[domain]["issues"].append(f"⚠️ Le certificat ne peut émettre que des certificats end user (pas d'autres CA)")
                        analysis_result[domain]["score"] += 5
                elif basic_constraints == "CA:FALSE":
                        analysis_result[domain]["issues"].append(f"❌ CA:FALSE -> Ne peut donc pas émettre d'autres certificats ")
                        analysis_result[domain]["score"] -= 10

# 2. crl_distribution_points
                crl = cert['crl_distribution_points']
                if crl:
                    analysis_result[domain]["score"] += 5
                    analysis_result[domain]["reason"].append(f"✔️ CRL distribution point present")
                else:
                    analysis_result[domain]["score"] -= 10
                    analysis_result[domain]["issues"].append(f"❌ Missing CRL distribution point")
# 3. key_usage:

                if 'digital signature' in key_usage.lower():
                    analysis_result[domain]["score"] += 5
                    analysis_result[domain]["reason"].append("✅ L'EKU inclus la Digital Signature")
                else:
                    analysis_result[domain]["score"] -= 10
                    analysis_result[domain]["issues"].append(f"⚠️ L’EKU ne contient pas la fonctionnalité de signature numérique (Digital Signature missing)")
#5. Subject Alternative Names (SANs)
                if subject_alt_name:
                    san_count = subject_alt_name.count("DNS:")
                    if san_count > 1:
                        analysis_result[domain]["score"] += 1
                        analysis_result[domain]["reason"].append(f"✅ Multiple SANs presents")
                    elif san_count == 1:
                        analysis_result[domain]["score"] += 1
                        analysis_result[domain]["reason"].append(f"✅ Single SAN present")
                    else:
                        analysis_result[domain]["score"] += 1
                        analysis_result[domain]["issues"].append(f"⚠️ SANs présents mais pas de type DNS")
                else:
                    analysis_result[domain]["score"] -= 5
                    analysis_result[domain]["issues"].append(f"❌ SANs manquants")
#6.Extended Key Usage (EKUs)
                if extended_key_usage:
                    eku = extended_key_usage
                    if eku and eku.strip().lower() not in ('none', ''):
                        analysis_result[domain]["score"] += 5
                        analysis_result[domain]["reason"].append(f"✅ l'EKU est défini")
                else:
                    analysis_result[domain]["score"] -= 5
                    analysis_result[domain]["issues"].append(f"⚠️ EKU manquant ou non défini")
                
# Log results
                logger.info(f"Analysis for {domain}:")
                logger.info(f"  - Domain: {domain}")
                logger.info(f"  - Organization: {issuer_o}")
                logger.info(f"  - Autorité émettrice: {issuer_aggregated}")
                logger.info(f"  - Trusted: {analysis_result[domain]['trusted']}")
                logger.info(f"  - Score de criticité: {analysis_result[domain]['score']}")
                logger.info(f"  - Remarques: {analysis_result[domain]['info']}")
                logger.info(f"  - Issues: {len(analysis_result[domain]['issues'])}")
                if analysis_result[domain]['issues']:
                        for issue in analysis_result[domain]['issues']:
                            logger.warning(f"    ! {issue}")
# Custom suspicious logging (your exact implementation)
                if analysis_result[domain]['score'] < 0:  # THRESHOLD
                    custom_logger = Logger(print_logs=True)
                    custom_logger.log_suspicious_domains(
                        analysis_result[domain]['score'], 
                        domain, 
                        issuer_aggregated
                    )
                save_alert(
                    domain=domain,
                    organization=issuer_o,
                    trusted=analysis_result[domain]['trusted'],
                    score=analysis_result[domain]['score'],
                    info=analysis_result[domain]['info'],
                    issues=analysis_result[domain]['issues']
                )
                
    if len(matched_issuers) == len(known_issuers):
        print("="*80)
        print("INFO - ✅ Tous les domaines ont été scannés. Arrêt du serveur Certstream...")
        sys.exit(0)
            
def generate_typosquats(base_domain=BASE_DOMAIN, output_filename="keywords.json"):
    CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789-.'
    # Découpe le domaine de base à chaque position
    splits = [(base_domain[:i], base_domain[i:]) for i in range(len(base_domain)+1)]
    
    # Générer les variations à distance 1 (supprimer, transposer, remplacer, insérer)
    deletes = [a + b[1:] for a, b in splits if b]
    transposes = [a + b[1] + b[0] + b[2:] for a, b in splits if len(b) > 1]
    replaces = [a + c + b[1:] for a, b in splits if b for c in CHARS]
    inserts = [a + c + b for a, b in splits for c in CHARS]
    
    # Combinaison et déduplication
    variations = set(deletes + transposes + replaces + inserts)
    variations.discard(base_domain)
    
    # Calculer les scores en utilisant le ratio de Levenshtein
    scored = {
        domain: round(ratio(base_domain, domain) * 100)
        for domain in variations
        if 3 <= len(domain) <= len(base_domain) + 5
    }
    
    # Retourner les domaines triés par score décroissant
    sorted_scored = dict(sorted(scored.items(), key=lambda x: -x[1]))
    
    # Sauvegarder directement dans un fichier JSON
    with open(output_filename, "w") as f:
        json.dump(sorted_scored, f, indent=2)
    
    print(f"Generated {len(sorted_scored)} typo-variations in {output_filename}")
    return sorted_scored

def test_config():
    print("✅ Configuration testée avec succès")

def start_analysis():
    print(f"[START] Analyse en temps réel des certificats SSL/TLS")
    
    global keywords, known_issuers, cert_infos
    logger.info("Loading keywords...")
    keywords = load_keywords(KEYWORDS_FILE)
    

    logger.info(f"Loaded {len(keywords)} keywords for analysis")
    logger.info("Starting certificate collection phase...")

    domains = list(keywords.keys())
    cert_infos = get_certificate_info(domains)
    
    # Extract normalized issuer names
    known_issuers = set(
    normalize_name(extract_common_name(item['issuer']))
    for item in cert_infos if 'issuer' in item and normalize_name(extract_common_name(item['issuer'])) != "unknown"
)

    # Start the real-time certificate stream
    certstream.listen_for_events(my_callback, url='wss://certstream-nizar.zerlina2012.synology.me')

def main():

    parser = argparse.ArgumentParser(description="Analyse en temps réel des certificats SSL/TLS")
    parser.add_argument('--start', action='store_true', help='Démarre l’analyse en temps réel')
    parser.add_argument('--test', action='store_true', help='Effectue un test de configuration')
    parser.add_argument('--typosquats', action='store_true', help='Génère des variantes typographiques avec mesure de similarité')
    args = parser.parse_args()

    if args.test:
        test_config()
    elif args.start:
        start_analysis()
    elif args.typosquats:
        generate_typosquats()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
