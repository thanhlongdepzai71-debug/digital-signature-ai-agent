import json
from datetime import datetime, timezone
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_file_with_custom_info(
    file_path: str,
    signer_name: str = "Diệp Thành Long",
    signature_type: str = "RSA-SHA256 (CAdES-Basic)"
):
    """
    Ký số nhúng kèm Tên người ký, Dấu thời gian (Timestamp), và Loại chữ ký
    """
    key_path = "keys/private_key.pem"
    cert_path = "keys/certificate.pem"

    # 1. Đọc dữ liệu file để tính toán Hash
    with open(file_path, "rb") as f:
        file_data = f.read()

    # 2. Đọc Private Key và Ký số SHA-256
    with open(key_path, "rb") as kf:
        private_key = serialization.load_pem_private_key(kf.read(), password=None)

    signature = private_key.sign(file_data, padding.PKCS1v15(), hashes.SHA256())

    # 3. Đọc Certificate X.509
    with open(cert_path, "r") as cf:
        cert_pem = cf.read()

    # 4. Tạo gói Metadata chứa Tên, Thời gian, Loại chữ ký
    signature_manifest = {
        "signer_info": {
            "signer_name": signer_name,
            "signature_type": signature_type,
            "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "algorithm": "RSA-2048 / SHA-256"
        },
        "signature_hex": signature.hex(),
        "certificate_pem": cert_pem
    }

    # 5. Nhúng gói Manifest này vào ID3 Metadata Tag của MP3
    try:
        audio = ID3(file_path)
    except ID3NoHeaderError:
        audio = ID3()

    manifest_json = json.dumps(signature_manifest, ensure_ascii=False, indent=2)
    audio.add(TXXX(encoding=3, desc="DIGITAL_SIGNATURE_MANIFEST", text=manifest_json))
    audio.save(file_path)

    return signature_manifest