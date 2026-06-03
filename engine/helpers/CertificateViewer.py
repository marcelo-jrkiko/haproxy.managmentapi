
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
            
class CertificateViewer:
    @staticmethod
    def get_details(cert_file: str | bytes):
        """Helper function to read certificate details from a .crt file."""
        try:
            if isinstance(cert_file, str):
                with open(cert_file, "rb") as f:
                    cert_data = f.read()
            else:
                cert_data = cert_file

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            details = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "version": cert.version.name,
            }
            
            return details
        except Exception as e:
            logging.getLogger(__name__).error(f"Error reading certificate details: {e}")
            return None