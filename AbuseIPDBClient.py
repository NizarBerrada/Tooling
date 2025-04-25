import socket
from BaseClient import BaseClient

class AbuseIPDBClient(BaseClient):
    def __init__(self, api_key):
        base_url = "https://api.abuseipdb.com/api/v2/"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        super().__init__(base_url=base_url, headers=headers)

    def check_reputation(self, ip= None, domain= None) :
        # Vérifier si l'IP ou le domaine est fourni
        if not ip and not domain:
            raise ValueError("IP ou domaine requis")

        # Si un domaine est fourni, essayer de le résoudre en IP
        if domain:
            try:
                ip = socket.gethostbyname(domain)  # Résolution DNS
                #print(f"[⏳] Domaine '{domain}' résolu en IP : {ip}")
            except socket.gaierror:
                #print(f"[❌] Aucune adresse IP {domain} trouvée sur AbuseIPDB")
                return {"ip": None, "score": 0}  # Si résolution échoue, retourner 0

        # Si aucune IP n'est fournie après résolution, lever une erreur
        if not ip:
            raise ValueError("IP requise pour la vérification de réputation")

        # Requête à l'API AbuseIPDB
        response = self.http_request(
            method="GET",
            endpoint="check",
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )

        # Vérifier si la réponse est valide
        if response and "data" in response:
            score = response["data"].get("abuseConfidenceScore", 0)  # Récupérer le score
            return {"ip": ip, "score": score}

        # Retourner 0 si aucune donnée valide n'est reçue
        print(f"[ERROR] Pas de réponse valide pour {domain or ip}")
        return {"ip": ip, "score": 0}