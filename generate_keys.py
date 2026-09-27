from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 1. Tạo Private Key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Lưu Private Key ra file private_key.pem
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# 3. Tạo và lưu Public Key ra file public_key.pem
public_key = private_key.public_key()
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("✅ Đã tạo thành công cặp khóa: private_key.pem và public_key.pem!")