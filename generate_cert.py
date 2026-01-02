from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import ipaddress

IP_ADDRESS = "127.0.0.1"

# Generate private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# Certificate subject & issuer
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, IP_ADDRESS)
])

# Build certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address(IP_ADDRESS))
        ]),
        critical=False
    )
    .sign(key, hashes.SHA256())
)

# Write key
# with open("wazuh-proxy.key", "wb") as f:
#     f.write(
#         key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption(),
#         )
#     )

# Write cert
# with open("wazuh-proxy.crt", "wb") as f:
#     f.write(cert.public_bytes(serialization.Encoding.PEM))

# Combine for mitmproxy
with open("wazuh-proxy.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

print("✔ Certificate generated: wazuh-proxy.pem")
