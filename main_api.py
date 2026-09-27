import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

app = FastAPI(title="Digital Signature AI Agent API")

# 1. BẬT CORS: Cho phép giao diện Web (GitHub Pages) gọi API không bị trình duyệt chặn
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# 2. HÀM HỖ TRỢ: Nạp Public Key để xác thực chữ ký
def load_public_key():
    key_path = os.path.join(BASE_DIR, "public_key.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=500, detail="Chưa tìm thấy file public_key.pem trên Server")
    with open(key_path, "rb") as f:
        return load_pem_public_key(f.read())


# 3. ENDPOINT: Lấy danh sách tệp âm thanh (bài giảng .mp3)
@app.get("/download-audio-list")
def get_audio_list():
    audio_files = []
    # Quét tất cả file trong thư mục dự án
    for file in os.listdir(BASE_DIR):
        if file.endswith(".mp3"):
            audio_files.append({"file_name": file})
    return audio_files


# 4. ENDPOINT: Tải hoặc phát trực tiếp file (PDF, DOCX, MP3)
@app.get("/download/{file_name}")
def download_file(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp yêu cầu")
    return FileResponse(path=file_path, filename=file_name)


# 5. ENDPOINT: Xác thực chữ ký số (.sig) của tệp bất kỳ
@app.get("/verify")
def verify_signature(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    sig_path = os.path.join(BASE_DIR, f"{file_name}.sig")

    # Kiểm tra sự tồn tại của file và file chữ ký số .sig tương ứng
    if not os.path.exists(file_path):
        return {"status": "ERROR", "valid": False, "message": f"Tệp {file_name} không tồn tại trên Server."}
    
    if not os.path.exists(sig_path):
        return {"status": "ERROR", "valid": False, "message": f"Không tìm thấy file chữ ký số ({file_name}.sig)."}

    try:
        # Đọc dữ liệu file và chữ ký
        with open(file_path, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        public_key = load_public_key()

        # Thực hiện xác thực bằng thuật toán RSA (SHA-256 PSS)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "status": "SUCCESS",
            "valid": True,
            "message": f"Xác thực thành công! Tệp '{file_name}' hợp lệ và giữ nguyên tính toàn vẹn."
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "valid": False,
            "message": f"Xác thực thất bại! Tệp '{file_name}' đã bị chỉnh sửa hoặc chữ ký không khớp."
        }