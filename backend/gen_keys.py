from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ed25519

# Fernet symmetric key (for field encryption)
with open("fernet.key", "wb") as f:
    f.write(Fernet.generate_key())

# Ed25519 signing keys
priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()

with open("ed25519_private.key", "wb") as f:
    f.write(priv.private_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=[""]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=[""]).PrivateFormat.PKCS8,
        encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization", fromlist=[""]).NoEncryption()
    ))

with open("ed25519_public.key", "wb") as f:
    f.write(pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=[""]).Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=[""]).PublicFormat.SubjectPublicKeyInfo
    ))

print("✅ Generated fernet.key, ed25519_private.key, ed25519_public.key")
