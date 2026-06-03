
import logging
import os
import shutil
import tempfile

from config import Config
from helpers.CertificateViewer import CertificateViewer
from helpers.CertStorageClient import CertStorageClient
from helpers.haproxy_manager import HaProxyManager
import utils


class PullSSLCertsTask:
    def __init__(self):    
        self.config = Config()        
        self.logger = logging.getLogger("PullSSLCerts Task")

    def run(self):
        # Placeholder for the logic to pull SSL certificates
        if self.config.CERTBUDDY_INTEGRATION_ENABLED:
            self.logger.info("Pulling SSL certificates from CertBuddy.")
            
            # List the configured domains 
            domains = HaProxyManager.list_domains()
            certStorage = CertStorageClient(self.config)
            
            # For each domain, try to find a matching certificate in Cert Storage and update the service configuration if a new certificate is found
            for domain_entry in domains:
                domain = domain_entry['domain']
                self.logger.info(f"Processing domain: {domain}")
                
                ssl_dir = self.config.SSL_CERT_DIR                    
                ssl_cert_path = os.path.join(ssl_dir, f"{domain}.pem")
                
                try:
                    if os.path.exists(ssl_cert_path):
                        # check the certifica still valid and not expiring soon
                        cert_details = CertificateViewer.get_details(ssl_cert_path)
                        if cert_details:
                            expires_at = cert_details.get("not_valid_after")
                            if utils.is_cert_expiring_soon(expires_at, self.config.RENEW_CERTS_AFTER_DAYS):
                                self.logger.info(f"Existing SSL certificate for domain {domain} is expiring soon (expires at {expires_at}). Attempting to pull a new certificate.")
                            else:
                                self.logger.info(f"Existing SSL certificate for domain {domain} is still valid (expires at {expires_at}). Skipping.")
                                continue   
                        else:
                            self.logger.warning(f"Could not read details of existing SSL certificate for domain {domain}. Attempting to pull a new certificate.")
                    
                    # Search for a matching certificate in Cert Storage for the domain
                    cert_search = certStorage.match_certificate_for_domain(domain)
                    if not cert_search or len(cert_search) == 0:
                        self.logger.warning(f"No matching certificate found in Cert Storage for domain {domain} . Skipping.")
                        continue
                    
                    # If a certificate is found, download it and update the service configuration with the new certificate and ssl_expires_at
                    cert_info = cert_search[0]
                    cert_id = cert_info.get("id")
                    
                    cert_details = certStorage.get_certificate(cert_id)
                    if not cert_details:
                        self.logger.error(f"Failed to get certificate details for certificate ID {cert_id} from Cert Storage. Skipping service.")
                        continue                                                    
                    
                    # Update the Local ATS Server with the new certificate and key files
                    temp_cert_bundle = f"{tempfile.gettempdir()}/{cert_id}_bundle.zip"
                    certStorage.download_certificate(cert_id, temp_cert_bundle)
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        shutil.unpack_archive(temp_cert_bundle, temp_dir)
                        cert_path = os.path.join(temp_dir, f"{domain}.crt")
                        key_path = os.path.join(temp_dir, f"{domain}.key")
                        
                        if os.path.exists(cert_path) and os.path.exists(key_path):
                            with open(ssl_cert_path, 'w') as ssl_cert_file:
                                with open(cert_path, 'r') as cert_file:
                                    ssl_cert_file.write(cert_file.read())
                                with open(key_path, 'r') as key_file:
                                    ssl_cert_file.write(key_file.read())
                            self.logger.info(f"SSL certificates installed successfully for domain {domain}")
                        else:
                            self.logger.error(f"Certificate or key file not found in the downloaded bundle for domain {domain}")   
                
                except Exception as e:
                    self.logger.error(f"Error processing domain {domain}: {str(e)}")
                    continue
        else:
            self.logger.info("CertBuddy integration is disabled. Skipping SSL certificate pull.")