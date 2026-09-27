import os
import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Thư viện phục vụ ký số PDF
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

app = FastAPI(title="Digital Signature AI Agent API")

# Cấu hình CORS để cho phép Frontend (GitHub Pages) truy cập
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
KEYS_DIR = "keys"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)


def get_pdf_signer():
    """Tự động khởi tạo và nạp cặp khóa RSA / Chứng thư số self-signed nếu chưa có"""
    key_path = os.path.join(KEYS_DIR, "selfsigned.key")
    cert_path = os.path.join(KEYS_DIR, "selfsigned.cert")

    if not (os.path.exists(key_path) and os.path.exists(cert_path)):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Tạo khóa tư RSA 2048-bit
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Tạo chứng thư số Self-Signed
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, u"Digital Signature AI Agent"
                ),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .sign(key, hashes.SHA256())
        )

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    return signers.SimpleSigner.load(key_path, cert_path)


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Digital Signature AI Agent API is running!"}


# LƯU Ý: Dùng 'def' thay vì 'async def' để FastAPI chạy endpoint trong threadpool riêng,
# tránh xung đột event loop khi pyhanko thực hiện thao tác ký số ngầm.
@app.post("/upload")
def upload_file(file: UploadFile = File(...)):
    raw_path = os.path.join(UPLOAD_DIR, f"raw_{file.filename}")
    signed_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        # 1. Lưu file nhận được vào đĩa
        with open(raw_path, "wb") as f:
            f.write(file.file.read())

        # 2. Nếu là file PDF thì tiến hành ký số RSA bằng PyHanko
        if file.filename.lower().endswith(".pdf"):
            signer = get_pdf_signer()
            with open(raw_path, "rb") as inf:
                w = IncrementalPdfFileWriter(inf)
                fields.append_signature_field(
                    w, sig_field_spec=fields.SigFieldSpec(sig_field_name="Signature1")
                )
                with open(signed_path, "wb") as outf:
                    signers.sign_pdf(
                        w,
                        signers.PdfSignatureMetadata(field_name="Signature1"),
                        signer=signer,
                        output=outf,
                    )
            # Xóa file chưa ký tạm thời sau khi ký xong
            if os.path.exists(raw_path):
                os.remove(raw_path)
        else:
            # File dạng khác PDF thì giữ nguyên
            os.rename(raw_path, signed_path)

        return {
            "message": f"Đã tải lên và tự động ký số RSA thành công cho {file.filename}!",
            "filename": file.filename,
        }
    except Exception as e:
        # Khôi phục file nếu có lỗi xảy ra trong quá trình ký
        if os.path.exists(raw_path) and not os.path.exists(signed_path):
            os.rename(raw_path, signed_path)
        raise HTTPException(status_code=500, detail=f"Lỗi ký số: {str(e)}")


@app.get("/files")
def list_files():
    if not os.path.exists(UPLOAD_DIR):
        return []
    files = os.listdir(UPLOAD_DIR)
    file_list = []
    for f in files:
        file_path = os.path.join(UPLOAD_DIR, f)
        if os.path.isfile(file_path) and not f.startswith("raw_"):
            file_list.append({"filename": f, "size": os.path.getsize(file_path)})
    return file_list


@app.get("/files/{filename}")
def get_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File không tồn tại")
    return FileResponse(file_path)