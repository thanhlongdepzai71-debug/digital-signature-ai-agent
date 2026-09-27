import os
import glob
import logging
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Digital Signature Lecture Manager API", version="2.2.0")

# Bật CORS cho phép kết nối từ mọi nguồn (GitHub Pages)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")

# Structure dữ liệu yêu cầu mật khẩu khi xóa
class DeleteRequest(BaseModel):
    password: str


# --- HÀM HỖ TRỢ KÝ SỐ TỰ ĐỘNG RSA SHA-256 ---
def auto_sign_file(file_path: str):
    if not os.path.exists(PRIVATE_KEY_PATH):
        return  # Bỏ qua nếu chưa cấu hình key trên server

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


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Digital Signature API đang hoạt động ổn định và mượt mà!"}


# --- 1. API UPLOAD & TỰ ĐỘNG KÝ SỐ ---
@app.post("/upload")
async def upload_audio(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(BASE_DIR, file.filename)

        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # Tự động tạo file .sig
        auto_sign_file(file_path)

        return {
            "status": "success",
            "message": f"Đã tải lên và tự động ký số thành công cho {file.filename}!",
            "file_name": file.filename,
            "sig_file": f"{file.filename}.sig"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- 2. API TRẢ VỀ DANH SÁCH FILE MP3 (JSON) ---
@app.get("/download-audio-list")
def get_audio_list():
    audio_files = []
    if os.path.exists(BASE_DIR):
        for file in os.listdir(BASE_DIR):
            if file.endswith(".mp3"):
                sig_exists = os.path.exists(os.path.join(BASE_DIR, f"{file}.sig"))
                audio_files.append({
                    "file_name": file,
                    "has_signature": sig_exists,
                    "signature_file": f"{file}.sig" if sig_exists else None
                })
    return audio_files


# --- 3. API TẢI XUỐNG DANH SÁCH FILE ĐÃ KÝ DƯỚI DẠNG FILE JSON RIÊNG ---
@app.get("/export-signed-list-json")
def export_signed_list_json():
    signed_records = []
    if os.path.exists(BASE_DIR):
        for file in os.listdir(BASE_DIR):
            if file.endswith(".mp3"):
                sig_path = os.path.join(BASE_DIR, f"{file}.sig")
                signed_records.append({
                    "file_name": file,
                    "signed": os.path.exists(sig_path),
                    "signature_filename": f"{file}.sig"
                })
    
    # Trả về dưới dạng file JSON để trình duyệt tự động tải xuống
    json_file_path = os.path.join(BASE_DIR, "signed_lectures_report.json")
    import json
    with open(json_file_path, "w", encoding="utf-8") as jf:
        json.dump(signed_records, jf, ensure_ascii=False, indent=4)
        
    return FileResponse(
        path=json_file_path, 
        filename="signed_lectures_report.json", 
        media_type="application/json"
    )


# --- 4. API PHÁT / TẢI FILE ---
@app.get("/download/{file_name}")
@app.get("/files/{file_name}")
def download_file(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp yêu cầu")
    return FileResponse(path=file_path, filename=file_name)


# --- 5. API XÁC THỰC CHỮ KÝ SỐ ---
@app.get("/verify")
@app.get("/verify/{file_name}")
def verify_signature(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    sig_path = os.path.join(BASE_DIR, f"{file_name}.sig")

    if not os.path.exists(file_path):
        return {"status": "REJECTED", "valid": False, "message": f"Tệp {file_name} không tồn tại."}
    
    if not os.path.exists(sig_path):
        return {"status": "REJECTED", "valid": False, "message": f"Không tìm thấy file chữ ký số ({file_name}.sig)."}

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = load_pem_public_key(f.read())

        # Xác minh chữ ký bằng RSA PSS SHA-256
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
            "status": "ACCEPTED",
            "valid": True,
            "message": f"Xác thực thành công! Tệp '{file_name}' hợp lệ và giữ nguyên tính toàn vẹn chữ ký số RSA."
        }

    except Exception:
        return {
            "status": "REJECTED",
            "valid": False,
            "message": f"Xác thực thất bại! Tệp '{file_name}' đã bị chỉnh sửa hoặc chữ ký không khớp."
        }


# --- 6. API XÓA BÀI GIẢNG (MẬT KHẨU BẢO MẬT) ---
@app.delete("/delete/{file_name}")
def delete_lecture(file_name: str, req: DeleteRequest):
    TEACHER_PASSWORD = os.getenv("TEACHER_PASSWORD", "Duymt123456@")

    if req.password != TEACHER_PASSWORD:
        raise HTTPException(status_code=401, detail="Mật khẩu Quản trị/Giảng viên không chính xác!")

    file_path = os.path.join(BASE_DIR, file_name)
    sig_path = os.path.join(BASE_DIR, f"{file_name}.sig")

    deleted_items = []

    if os.path.exists(file_path):
        os.remove(file_path)
        deleted_items.append(file_name)

    if os.path.exists(sig_path):
        os.remove(sig_path)
        deleted_items.append(f"{file_name}.sig")

    if not deleted_items:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy bài giảng '{file_name}' để xóa.")

    return {
        "status": "success",
        "message": f"Xác thực thành công! Đã xóa bài giảng '{file_name}' và chữ ký số đính kèm.",
        "deleted_files": deleted_items
    }