# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

observable_certificate = opencti_api_client.stix_cyber_observable.create(
    observableData={
        "type": "x509-certificate",
        "hashes": {
            "SHA-1": "3ba7e9f806eb30d2f4e3f905e53f07e9acf08e1e",
            "SHA-256": "73b8ed5becf1ba6493d2e2215a42dfdc7877e91e311ff5e59fb43d094871e699",
            "MD5": "956f4b8a30ec423d4bbec9ec60df71df",
        },
        "serial_number": "3311565258528077731295218946714536456",
        "signature_algorithm": "SHA256-RSA",
        "issuer": "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
        "validity_not_before": "2025-01-02T00:00:00Z",
        "validity_not_after": "2026-01-21T23:59:59Z",
        "subject": "C=US, ST=California, L=San Francisco, O=Cloudflare\\, Inc., CN=cloudflare-dns.com",
        "subject_public_key_algorithm": "ECDSA",
        "authority_key_identifier": "748580c066c7df37decfbd2937aa031dbeedcd17",
        "basic_constraints": '{"is_ca":null,"max_path_len":null}',
        "certificate_policies": "[CertificatePolicy(cps=['http://www.digicert.com/CPS'], id='2.23.140.1.2.2', user_notice=Unset())]",
        "crl_distribution_points": "['http://crl3.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl', 'http://crl4.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crl']",
        "extended_key_usage": '{"client_auth":true,"server_auth":true}',
        "key_usage": '{"certificate_sign":null,"content_commitment":null,"crl_sign":null,"data_encipherment":null,"decipher_only":null,"digital_signature":true,"encipher_only":null,"key_agreement":true,"key_encipherment":null,"value":17}',
    }
)

print(observable_certificate)
