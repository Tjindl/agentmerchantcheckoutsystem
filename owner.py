"""The Human Owner: creates an RSA key pair and signs a Digital Agent Passport (JWT)."""
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 1. Generate the owner's key pair. The private key never leaves this script.
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2. Publish the public key so the backend can verify passports.
with open("public_key.pem", "wb") as f:
    f.write(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

# 3. Sign the passport: what this agent is allowed to do on the owner's behalf.
passport = jwt.encode(
    {"user_id": "usr_99", "max_spend": 100, "allowed_category": "cloud_compute"},
    private_key,
    algorithm="RS256",
)
print(passport)
