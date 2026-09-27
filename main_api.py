import os
import zipfile
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Thư viện Mật mã RSA & X.509
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Thư viện xử lý ID3 Tag cho MP3
from mutagen.id3 import ID3, TXXX, ID3NoHeaderError

# Thư viện ký số PDF chuẩn PKCS#7
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

app = FastAPI(title="Hệ Thống Ký Số RSA & Quản Lý Bài Giảng API")

# Cấu hình CORS để GitHub Pages gọi API không bị chặn
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

# Cho phép truy cập /files trực tiếp để tải file
app.mount("/files", StaticFiles(directory=SIGNED_DIR), name="files")

KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
CERT_PATH = os.path.join(KEYS_DIR, "certificate.pem")


# ==========================================
# 1. HÀM TẠO TỰ ĐỘNG CẶP KHÓA RSA & CERTIFICATE
# ==========================================
def ensure_keys_exist():
    """Tạo Private Key và Self-Signed Certificate nếu chưa có."""
    if not os.path.exists(KEY_PATH) or not os.path.exists(CERT_PATH):
        # Tạo RSA Private Key (2048-bit)
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

        # Tạo Certificate X.509
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "He Thong Ky So AI Agent"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dai Hoc"),
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


# ==========================================
# 2. CÁC HÀM XỬ LÝ KÝ SỐ MỖI ĐỊNH DẠNG
# ==========================================
def sign_pdf_file(input_path: str, output_path: str):
    """Nhúng chữ ký số PKCS#7 trực tiếp vào file PDF."""
    key_p, cert_p = ensure_keys_exist()
    signer = signers.SimpleSigner.load(
        key_file=key_p,
        cert_file=cert_p,
    )
    with open(input_path, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(sig_field_name="Signature1")
        )
        with open(output_path, "wb") as outf:
            signers.sign_pdf(
                w,
                signers.PdfSignatureMetadata(field_name="Signature1"),
                signer=signer,
                output=outf,
            )


def sign_mp3_directly(file_path: str):
    """Nhúng Chữ ký RSA & Certificate trực tiếp vào thẻ ID3 Metadata của file MP3."""
    key_p, cert_p = ensure_keys_exist()

    # Đọc dữ liệu audio để tính chữ ký SHA-256
    with open(file_path, "rb") as f:
        data = f.read()

    with open(key_p, "rb") as kf:
        private_key = serialization.load_pem_private_key(kf.read(), password=None)

    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    sig_hex = signature.hex()

    with open(cert_p, "r") as cf:
        cert_pem = cf.read()

    # Thêm Metadata vào thẻ ID3v2
    try:
        audio = ID3(file_path)
    except ID3NoHeaderError:
        audio = ID3()

    audio.add(TXXX(encoding=3, desc="DIGITAL_SIGNATURE_RSA", text=sig_hex))
    audio.add(TXXX(encoding=3, desc="DIGITAL_CERTIFICATE", text=cert_pem))
    audio.save(file_path)


def sign_generic_detached(file_path: str, filename: str) -> str:
    """Tạo chữ ký rời (.sig) và nén thành ZIP cho các định dạng khác (PPTX, DOCX...)."""
    key_p, _ = ensure_keys_exist()

    with open(file_path, "rb") as f:
        data = f.read()

    with open(key_p, "rb") as kf:
        private_key = serialization.load_pem_private_key(kf.read(), password=None)

    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    sig_filename = f"{filename}.sig"
    sig_path = os.path.join(SIGNED_DIR, sig_filename)
    with open(sig_path, "wb") as sf:
        sf.write(signature)

    # Đóng gói thành ZIP chứa File Gốc + File Chữ ký rời
    zip_filename = f"{filename}.zip"
    zip_path = os.path.join(SIGNED_DIR, zip_filename)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, arcname=filename)
        zipf.write(sig_path, arcname=sig_filename)

    # Dọn dẹp file .sig tạm
    if os.path.exists(sig_path):
        os.remove(sig_path)

    return zip_filename


# ==========================================
# 3. API ENDPOINTS
# ==========================================
@app.get("/")
def home():
    return {"status": "ok", "message": "Hệ thống Ký Số RSA & Quản lý Bài giảng đang hoạt động!"}


@app.get("/files")
def get_files():
    """Lấy danh sách bài giảng/tài liệu đã được lưu trữ."""
    result = []
    for fn in os.listdir(SIGNED_DIR):
        fp = os.path.join(SIGNED_DIR, fn)
        if os.path.isfile(fp):
            result.append({
                "filename": fn,
                "size": os.path.getsize(fp)
            })
    return result


@app.post("/upload")
def upload_file(file: UploadFile = File(...)):
    """Tải file lên và thực hiện ký số phù hợp theo định dạng."""
    raw_path = os.path.join(SIGNED_DIR, f"temp_{file.filename}")

    with open(raw_path, "wb") as f:
        f.write(file.file.read())

    ext = os.path.splitext(file.filename)[1].lower()

    try:
        if ext == ".pdf":
            signed_filename = f"signed_{file.filename}"
            signed_path = os.path.join(SIGNED_DIR, signed_filename)
            sign_pdf_file(raw_path, signed_path)
            if os.path.exists(raw_path):
                os.remove(raw_path)
            final_name = signed_filename
            msg = "Đã nhúng chữ ký số PKCS#7 trực tiếp vào file PDF thành công!"

        elif ext == ".mp3":
            signed_path = os.path.join(SIGNED_DIR, file.filename)
            if os.path.exists(signed_path):
                os.remove(signed_path)
            os.rename(raw_path, signed_path)
            sign_mp3_directly(signed_path)
            final_name = file.filename
            msg = "Đã nhúng chữ ký số RSA & Chứng thư trực tiếp vào ID3 Tag của file MP3!"

        else:
            final_name = sign_generic_detached(raw_path, file.filename)
            if os.path.exists(raw_path):
                os.remove(raw_path)
            msg = f"Đã ký số bằng Chữ ký rời (Detached Signature) và đóng gói thành tệp ZIP `{final_name}`!"

        return {"message": msg, "filename": final_name}

    except Exception as e:
        if os.path.exists(raw_path):
            os.remove(raw_path)
        raise HTTPException(status_code=500, detail=f"Lỗi khi ký số: {str(e)}")


@app.delete("/delete/{filename}")
def delete_file(filename: str):
    """Xóa bài giảng/tài liệu khỏi hệ thống."""
    file_path = os.path.join(SIGNED_DIR, filename)

    # Bảo vệ không cho xóa đường dẫn ngoài thư mục
    if not os.path.abspath(file_path).startswith(SIGNED_DIR):
        raise HTTPException(status_code=400, detail="Thao tác không hợp lệ!")

    if os.path.exists(file_path) and os.path.isfile(file_path):
        os.remove(file_path)
        return {"message": f"Đã xóa file `{filename}` thành công!"}
    else:
        raise HTTPException(status_code=404, detail="Không tìm thấy file để xóa.")


@app.post("/verify-mp3")
def verify_mp3_signature(file: UploadFile = File(...)):
    """Trích xuất Chữ ký nhúng trong thẻ ID3 Tag của MP3 và xác minh tính toàn vẹn."""
    temp_path = os.path.join(SIGNED_DIR, f"verify_{file.filename}")
    with open(temp_path, "wb") as f:
        f.write(file.file.read())

    try:
        audio = ID3(temp_path)
        sig_hex = None
        cert_pem = None

        for frame in audio.getall("TXXX"):
            if frame.desc == "DIGITAL_SIGNATURE_RSA":
                sig_hex = frame.text[0]
            elif frame.desc == "DIGITAL_CERTIFICATE":
                cert_pem = frame.text[0]

        if not sig_hex or not cert_pem:
            os.remove(temp_path)
            return {
                "valid": False,
                "message": "Không tìm thấy Chữ ký số RSA nhúng trong ID3 Tag của file MP3 này!"
            }

        # Xác thực bằng Public Key từ Certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        public_key = cert.public_key()
        signature = bytes.fromhex(sig_hex)

        with open(temp_path, "rb") as f:
            data = f.read()

        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        os.remove(temp_path)

        return {
            "valid": True,
            "message": "Xác thực thành công! File MP3 chứa Chữ ký số RSA hợp lệ và dữ liệu còn nguyên bản.",
            "issuer": cert.issuer.rfc4514_string()
        }

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {
            "valid": False,
            "message": f"Xác thực thất bại: Chữ ký không hợp lệ hoặc dữ liệu đã bị can thiệp! ({str(e)})"
        }