import os
import json
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Cryptography & X.509
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ID3 Tag cho MP3
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError

# Ký số chuẩn PKCS#7 cho PDF (PyHanko)
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import SigFieldSpec

# Xử lý ký nhúng cho DOCX (OpenXML Signature)
import docx

app = FastAPI(title="Hệ Thống Ký Số RSA & Quản Lý Bài Giảng API")

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
async def upload_file(
    file: UploadFile = File(...),
    signer_name: str = Form("Diệp Thành Long"),
    signature_type: str = Form("RSA-SHA256 (CAdES-Basic)")
):
    key_p, cert_p = ensure_keys_exist(signer_name)
    raw_path = os.path.join(SIGNED_DIR, file.filename)
    file_bytes = await file.read()

    ext = os.path.splitext(file.filename)[1].lower()

    # 1. KÝ NHÚNG TRỰC TIẾP VÀO MP3 (ID3 Metadata)
    if ext == ".mp3":
        with open(raw_path, "wb") as f:
            f.write(file_bytes)

        with open(key_p, "rb") as kf:
            private_key = serialization.load_pem_private_key(kf.read(), password=None)

        signature = private_key.sign(file_bytes, padding.PKCS1v15(), hashes.SHA256())

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

        return {"message": f"Đã nhúng Chữ ký số thành công vào file MP3!", "filename": file.filename}

    # 2. KÝ NHÚNG TRỰC TIẾP VÀO PDF (NATIVE PKCS#7 / PAdES)
    elif ext == ".pdf":
        temp_in = os.path.join(SIGNED_DIR, f"temp_{file.filename}")
        with open(temp_in, "wb") as f:
            f.write(file_bytes)

        signer = signers.SimpleSigner.load(
            key_file=key_p,
            cert_file=cert_p,
            key_passphrase=None
        )

        with open(temp_in, "rb") as inf:
            w = IncrementalPdfFileWriter(inf)
            fields.append_signature_field(
                w, sigfield_spec=SigFieldSpec(sig_field_name="Signature1")
            )
            with open(raw_path, "wb") as outf:
                await signers.async_sign_pdf(
                    w,
                    signers.PdfSignatureMetadata(field_name="Signature1", reason="Digital Signature Authentication"),
                    signer=signer,
                    output=outf
                )

        if os.path.exists(temp_in):
            os.remove(temp_in)

        return {"message": f"Đã nhúng Chữ ký số PKCS#7 trực tiếp vào tệp PDF!", "filename": file.filename}

    # 3. KÝ NHÚNG TRỰC TIẾP VÀO DOCX (CUSTOM DOCUMENT PROPERTIES METADATA)
    elif ext == ".docx":
        temp_docx = os.path.join(SIGNED_DIR, f"temp_{file.filename}")
        with open(temp_docx, "wb") as f:
            f.write(file_bytes)

        # Đọc private key tính signature
        with open(key_p, "rb") as kf:
            private_key = serialization.load_pem_private_key(kf.read(), password=None)
        signature = private_key.sign(file_bytes, padding.PKCS1v15(), hashes.SHA256())

        # Mở file Docx và chèn trực tiếp Metadata người ký vào thuộc tính Document Properties
        doc = docx.Document(temp_docx)
        doc.core_properties.author = signer_name
        doc.core_properties.comments = f"Digital Signature RSA-SHA256 | Signed by {signer_name} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | SigHex: {signature.hex()[:32]}..."
        doc.save(raw_path)

        if os.path.exists(temp_docx):
            os.remove(temp_docx)

        return {"message": f"Đã nhúng Chữ ký số RSA trực tiếp vào thuộc tính của tệp DOCX!", "filename": file.filename}

    else:
        # Với các định dạng khác, lưu nguyên tệp
        with open(raw_path, "wb") as f:
            f.write(file_bytes)
        return {"message": f"Đã tải lên tệp {file.filename}", "filename": file.filename}


@app.delete("/delete/{filename}")
def delete_file(filename: str):
    file_path = os.path.join(SIGNED_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"message": "Đã xóa file thành công!"}
    raise HTTPException(status_code=404, detail="File không tồn tại.")