
import logging
import os
from typing import Any, Dict
import requests
from config import Config

class CertStorageClient:
    def __init__(self, config: Config):
        self.base_url = config.CERTBUDDY['url']
        self.token = config.CERTBUDDY['api_key']
        self.logger = logging.getLogger(self.__class__.__name__)
         
    def _make_request(self, method: str, endpoint: str, params: Dict[str, Any] = None, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make a direct HTTP request to the Directus API"""
        url = f"{self.base_url}{endpoint}"
        response = None
        
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, params=params, verify=False)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, verify=False)
            elif method == "PATCH":
                response = requests.patch(url, headers=self.headers, json=data, verify=False)
            elif method == "DELETE":
                response = requests.delete(url, headers=self.headers, verify=False)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            if(response.status_code >= 400):
                logging.error(f"Backend request failed: {response.status_code} \r\n\t - {response.text}")
                response.raise_for_status()                
            
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            logging.error(f"Backend request failed: {e} -> {response.text if response else 'No response'}")
            raise Exception(f"Failed to request the backend!")
        
    def setTokenToRootUser(self):
        """Set the authentication token to the root user token from configuration"""
        root_token = os.getenv('CERT_STORAGE_ROOT_USER_TOKEN', '')

        if not root_token:
            logging.error("Root user token not found in configuration!")
            raise Exception("Root user token not found in configuration!")
        self.setToken(root_token)
        
    def match_certificate_for_domain(self, domain):
        """Call the Cert Storage API to find a certificate matching the given domain"""
        try:
            items = self._make_request("GET", f"/certificates/match/{domain}")
            return items[0] if len(items) > 0 else None
        except Exception as e:
            self.logger.error(f"Failed to match certificate for domain {domain}: {e}")
            raise Exception(f"Failed to match certificate for domain {domain}!")
     
    def download_certificate(self, id: str, destination_path: str):
        """Download the certificate bundle for a given domain and save it to the specified path"""
        try:
            response = requests.get(f"{self.base_url}/certificates/{id}/download", headers=self.headers, verify=False)
            
            response.raise_for_status()  # Raise an error for bad status codes
            
            with open(destination_path, 'wb') as f:
                f.write(response.content)
                
            self.logger.info(f"Certificate for domain {id} downloaded successfully to {destination_path}")
        except Exception as e:
            self.logger.error(f"Failed to download certificate for domain {id}: {e}")
            raise Exception(f"Failed to download certificate for domain {id}!")
        
    def get_certificate(self, id: str):
        """Get the certificate for a given domain from the cert storage service"""
        try:
            items = self._make_request("GET", f"/certificates?id={id}")
            return items[0] if len(items) > 0 else None
        except Exception as e:
            self.logger.error(f"Failed to get certificate for domain {id}: {e}")
            raise Exception(f"Failed to get certificate for domain {id}!")
        
    def get_client_token(self, client_id):
        # Search for the client and login to generate a token
        client = self.backendClient.get_client(client_id=client_id)
        if not client:
            raise Exception(f"Client with ID '{client_id}' not found in the backend.")
        
        # Get the config of the client
        config = client.get("config", {})
        if not config.get("cert_storage_account_id"):
            raise Exception(f"Client with ID '{client_id}' does not have a cert_storage_account_id.")
        
        return config["cert_storage_token"]
    