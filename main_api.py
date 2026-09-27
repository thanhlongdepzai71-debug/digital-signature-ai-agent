import os
import time
import zipfile
import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Thư viện phục vụ ký số PDF
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

# Thư viện mã hóa RSA cho file tổng quát (Âm thanh, Video, Docx...)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = FastAPI(title="Digital Signature AI Agent API")

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


def ensure_keys_exist():
    """Khởi tạo cặp khóa RSA & Khai báo Chứng thư số nếu chưa tồn tại"""
    key_path = os.path.join(KEYS_DIR, "selfsigned.key")
    cert_path = os.path.join(KEYS_DIR, "selfsigned.cert")

    if not (os.path.exists(key_path) and os.path.exists(cert_path)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, u"Digital Signature AI Agent")]
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

    return key_path, cert_path


def get_pdf_signer():
    """Lấy signer dùng cho PyHanko (File PDF)"""
    key_path, cert_path = ensure_keys_exist()
    return signers.SimpleSigner.load(key_path, cert_path)


def sign_generic_file(file_path: str) -> str:
    """Ký số RSA cho file âm thanh & file bất kỳ (Tạo chữ ký rời .sig & nén file .zip)"""
    key_path, _ = ensure_keys_exist()

    with open(key_path, "rb") as kf:
        private_key = serialization.load_pem_private_key(kf.read(), password=None)

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    sig_path = f"{file_path}.sig"
    with open(sig_path, "wb") as sf:
        sf.write(signature)

    zip_path = f"{file_path}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, arcname=os.path.basename(file_path))
        zipf.write(sig_path, arcname=os.path.basename(sig_path))

    if os.path.exists(sig_path):
        os.remove(sig_path)

    return zip_path


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Digital Signature AI Agent API is running!"}


@app.post("/upload")
def upload_file(file: UploadFile = File(...)):
    raw_path = os.path.join(UPLOAD_DIR, f"raw_{file.filename}")
    signed_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        with open(raw_path, "wb") as f:
            f.write(file.file.read())

        if file.filename.lower().endswith(".pdf"):
            signer = get_pdf_signer()
            sig_field_name = f"Sig_{int(time.time())}"

            with open(raw_path, "rb") as inf:
                w = IncrementalPdfFileWriter(inf)
                fields.append_signature_field(
                    w, sig_field_spec=fields.SigFieldSpec(sig_field_name=sig_field_name)
                )
                with open(signed_path, "wb") as outf:
                    signers.sign_pdf(
                        w,
                        signers.PdfSignatureMetadata(field_name=sig_field_name),
                        signer=signer,
                        output=outf,
                    )
            if os.path.exists(raw_path):
                os.remove(raw_path)

            final_filename = file.filename
            msg = f"Đã tự động ký số RSA thành công cho file PDF {file.filename}!"

        else:
            zip_filename = f"{file.filename}.zip"
            zip_output_path = os.path.join(UPLOAD_DIR, zip_filename)

            zip_created = sign_generic_file(raw_path)

            if os.path.exists(zip_output_path):
                os.remove(zip_output_path)
            os.rename(zip_created, zip_output_path)

            if os.path.exists(raw_path):
                os.remove(raw_path)

            final_filename = zip_filename
            msg = f"Đã tạo file chữ ký rời RSA (.sig) và đóng gói dạng .zip thành công cho {file.filename}!"

        return {
            "message": msg,
            "filename": final_filename,
        }

    except Exception as e:
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


# --- ENDPOINT XÓA FILE ---
@app.delete("/delete/{filename}")
def delete_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File không tồn tại")
    
    try:
        os.remove(file_path)
        return {"message": f"Đã xóa thành công file {filename}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Không thể xóa file: {str(e)}")