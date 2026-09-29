import os
import json
import zipfile
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Thư viện Cryptography & X.509
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Thư viện ID3 cho MP3
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError

# Thư viện Ký PDF
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

# KHỞI TẠO BIẾN APP BẮT BUỘC ĐỂ UVICORN BẮT ĐƯỢC
app = FastAPI(title="Hệ Thống Ký Số RSA & Quản Lý Bài Giảng API")

# Cấu hình CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
SIGNED_DIR = os.path.join(BASE_DIR, "signed_files")

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

app.mount("/files", StaticFiles(directory=SIGNED_DIR), name="files")

KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
CERT_PATH = os.path.join(KEYS_DIR, "certificate.pem")


def ensure_keys_exist(signer_name: str = "Diệp Thành Long"):
    """Tạo Private Key và Certificate chứa thông tin người ký"""
    if not os.path.exists(KEY_PATH) or not os.path.exists(CERT_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, signer_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FPT University"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AI & CyberSecurity Lab"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    return KEY_PATH, CERT_PATH


@app.get("/")
def home():
    return {"status": "ok", "message": "Hệ thống Ký Số RSA đang chạy!"}


@app.get("/files")
def get_files():
    result = []
    for fn in os.listdir(SIGNED_DIR):
        fp = os.path.join(SIGNED_DIR, fn)
        if os.path.isfile(fp):
            result.append({"filename": fn, "size": os.path.getsize(fp)})
    return result


@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    signer_name: str = Form("Diệp Thành Long"),
    signature_type: str = Form("RSA-SHA256 (CAdES-Basic)")
):
    key_p, cert_p = ensure_keys_exist(signer_name)
    raw_path = os.path.join(SIGNED_DIR, file.filename)

    with open(raw_path, "wb") as f:
        f.write(file.file.read())

    ext = os.path.splitext(file.filename)[1].lower()

    if ext == ".mp3":
        with open(raw_path, "rb") as f:
            file_data = f.read()

        with open(key_p, "rb") as kf:
            private_key = serialization.load_pem_private_key(kf.read(), password=None)

        signature = private_key.sign(file_data, padding.PKCS1v15(), hashes.SHA256())

        with open(cert_p, "r") as cf:
            cert_pem = cf.read()

        manifest = {
            "signer_info": {
                "signer_name": signer_name,
                "signature_type": signature_type,
                "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "algorithm": "RSA-2048 / SHA-256"
            },
            "signature_hex": signature.hex(),
            "certificate_pem": cert_pem
        }

        try:
            audio = ID3(raw_path)
        except ID3NoHeaderError:
            audio = ID3()

        audio.add(TXXX(encoding=3, desc="DIGITAL_SIGNATURE_MANIFEST", text=json.dumps(manifest, ensure_ascii=False)))
        audio.save(raw_path)

        return {"message": f"Đã nhúng Chữ ký số RSA + Tên người ký ({signer_name}) trực tiếp vào ID3 Tag của tệp MP3!", "filename": file.filename}

    return {"message": "Đã lưu tệp!", "filename": file.filename}


@app.delete("/delete/{filename}")
def delete_file(filename: str):
    file_path = os.path.join(SIGNED_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"message": "Đã xóa file thành công!"}
    raise HTTPException(status_code=404, detail="File không tồn tại.")


@app.post("/verify-mp3")
def verify_mp3_signature(file: UploadFile = File(...)):
    temp_path = os.path.join(SIGNED_DIR, f"temp_v_{file.filename}")
    with open(temp_path, "wb") as f:
        f.write(file.file.read())

    try:
        audio = ID3(temp_path)
        manifest_json = None

        for frame in audio.getall("TXXX"):
            if frame.desc == "DIGITAL_SIGNATURE_MANIFEST":
                manifest_json = frame.text[0]

        if not manifest_json:
            os.remove(temp_path)
            return {"valid": False, "message": "Không tìm thấy Chữ ký số RSA nhúng trong ID3 Tag!"}

        manifest = json.loads(manifest_json)
        sig_hex = manifest.get("signature_hex")
        cert_pem = manifest.get("certificate_pem")
        signer_info = manifest.get("signer_info")

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        public_key = cert.public_key()
        signature = bytes.fromhex(sig_hex)

        with open(temp_path, "rb") as f:
            data = f.read()

        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        os.remove(temp_path)

        return {
            "valid": True,
            "message": "Chữ ký hợp lệ! Dữ liệu MP3 đảm bảo tính toàn vẹn và nguồn gốc.",
            "signer_info": signer_info
        }

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {"valid": False, "message": f"Xác thực thất bại: {str(e)}"}