import requests
class BaseClient:
    def __init__(self, base_url: str, headers: dict = {}):
        self.base_url = base_url
        self.default_headers = headers

    def http_request(self, method: str, endpoint: str = "", params: dict = None, json_body: dict = None, headers: dict = {}, verify_ssl: bool = True):
        url = f"{self.base_url}{endpoint}"
        final_headers = {**self.default_headers, **headers}

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                headers=final_headers,
                verify=verify_ssl
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[HTTP ERROR] {e}")
            return None