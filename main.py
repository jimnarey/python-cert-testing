#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def read_file_binary(path):
    with open(path, 'rb') as f:
        return f.read()

def subject_string(cert):
    return cert.subject.rfc4514_string()

# See 'X.509 Certificate Object' https://cryptography.io/en/latest/x509/reference/
def validate_cert(child, parent):
    try:
        parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
            padding.PKCS1v15(), child.signature_hash_algorithm)
        print('Success: {} was signed by {}'.format(subject_string(child), subject_string(parent)))
    except InvalidSignature as e:
        print('Error: {} was not signed by {}'.format(subject_string(child), subject_string(parent)))

def is_cert_intermediate(cert):
    return bool(cert.subject != cert.issuer)

root_cert_data = read_file_binary('./certs/python-rootca.pem')
root_cert = x509.load_pem_x509_certificate(root_cert_data)

intcaone_cert_data  = read_file_binary('./certs/python-intcaone.pem')
intcaone_cert = x509.load_pem_x509_certificate(intcaone_cert_data)

intcaone_client_cert_data = read_file_binary('./certs/python-client-intcaone-signed.pem')
intcaone_client_cert = x509.load_pem_x509_certificate(intcaone_client_cert_data)

intcatwo_client_cert_data = read_file_binary('./certs/python-client-intcatwo-signed.pem')
intcatwo_client_cert = x509.load_pem_x509_certificate(intcatwo_client_cert_data)

# Check that intcaone_client_cert was signed by intcaone_cert
validate_cert(intcaone_client_cert, intcaone_cert)

# Check that the validation works
validate_cert(intcatwo_client_cert, intcaone_cert)

# Check whether the root_cert is an intermediate
print(is_cert_intermediate(root_cert))

# Check whether the intcaone_cert is an intermediate
print(is_cert_intermediate(intcaone_cert))
