import os
from dotenv import load_dotenv

load_dotenv()

BASE_DOMAIN = "pepito.com"
API_KEY = os.getenv("API_KEY")
KEYWORDS_FILE = "./keywords.json"
LOGFILE = "{}/suspicious_domains.log".format(os.path.dirname(os.path.abspath(__file__)))

patata="vtava"
# Trusted and blacklisted CAs (expanded lists)
TRUSTED_ORGS = [
    "DigiCert Inc", "GlobalSign", "Sectigo Limited", 
    "GoDaddy", "Entrust", "Amazon", "Google Trust Services",
    "Microsoft", "Apple", "Comodo", "GeoTrust", "Thawte"
]

BLACKLISTED_ORGS = [
    "Let's Encrypt", "WoSign CA Limited", 
    "StartCom Certification Authority", "Hong Kong Post",
    "CNNIC", "China Internet Network Information Center",
    "TurkTrust", "TURKTRUST", "ANSSI", "Dodo"
]