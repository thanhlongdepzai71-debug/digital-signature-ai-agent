import os
import glob
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

app = FastAPI()

# Bật CORS để Web GitHub Pages gọi API từ Render mượt mà
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "."
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

# --- HÀM HỖ TRỢ KÝ SỐ TỰ ĐỘNG ---
def auto_sign_file(file_path: str):
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise Exception("Không tìm thấy file private_key.pem trên Server!")

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = f"{file_path}.sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(signature)


# --- 1. API UPLOAD & TỰ ĐỘNG KÝ SỐ ---
@app.post("/upload")
async def upload_audio(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        # Lưu file tải lên
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Tự động ký số tạo file .sig
        auto_sign_file(file_path)

        return {
            "status": "success",
            "message": f"Đã tải lên và tự động ký số thành công cho {file.filename}!",
            "file_name": file.filename,
            "sig_file": f"{file.filename}.sig"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- 2. API TRẢ VỀ DANH SÁCH FILE AUDIO (JSON) ---
@app.get("/download-audio-list")
async def get_audio_list():
    # Lấy toàn bộ file .mp3 trong thư mục
    mp3_files = glob.glob("*.mp3")
    result = [{"file_name": f} for f in mp3_files]
    return result


# --- 3. API PHÁT/TẢI FILE AUDIO HOẶC TÀI LIỆU ---
@app.get("/files/{filename}")
async def get_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="File không tồn tại!")


# --- 4. API XÁC THỰC CHỮ KÝ SỐ ---
@app.get("/verify/{filename}")
async def verify_signature(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    sig_path = f"{file_path}.sig"

    if not os.path.exists(file_path):
        return {"status": "REJECTED", "message": f"Không tìm thấy file {filename}"}
    
    if not os.path.exists(sig_path):
        return {"status": "REJECTED", "message": f"Không tìm thấy file chữ ký {filename}.sig"}

    if not os.path.exists(PUBLIC_KEY_PATH):
        return {"status": "REJECTED", "message": "Không tìm thấy Public Key trên Server"}

    try:
        # Đọc public key
        with open(PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())

        # Đọc dữ liệu file và chữ ký
        with open(file_path, "rb") as f:
            file_data = f.read()

        with open(sig_path, "rb") as sig_f:
            signature = sig_f.read()

        # Xác thực chữ ký RSA
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "status": "ACCEPTED",
            "message": f"Chữ ký hợp lệ! File {filename} toàn vẹn và đúng do tác giả ký."
        }
    except Exception:
        return {
            "status": "REJECTED",
            "message": f"Chữ ký KHÔNG hợp lệ! File {filename} có thể đã bị can thiệp/sửa đổi."
        }