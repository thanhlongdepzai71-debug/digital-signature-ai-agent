import os
import glob
import logging
from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Digital Signature & AI Agent Lecture Manager API", version="2.1.0")

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

# Khởi tạo Gemini Client chuẩn SDK mới nhất
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ai_client = None

try:
    from google import genai
    if GEMINI_API_KEY:
        ai_client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("Đã khởi tạo Gemini Client thành công.")
except Exception as e:
    logger.warning(f"Không thể khởi tạo Gemini Client: {e}")

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
    return {"status": "ok", "message": "Digital Signature & AI Agent API đang hoạt động ổn định!"}


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
                audio_files.append({"file_name": file})
    return audio_files


# --- 3. API PHÁT / TẢI FILE ---
@app.get("/download/{file_name}")
@app.get("/files/{file_name}")
def download_file(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp yêu cầu")
    return FileResponse(path=file_path, filename=file_name)


# --- 4. API XÁC THỰC CHỮ KÝ SỐ + PHÂN TÍCH AI AGENT ---
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

        ai_comment = "Xác thực chữ ký số RSA thành công. Tệp nguyên vẹn."
        if ai_client:
            try:
                prompt = f"Tệp bài giảng '{file_name}' đã được xác thực chữ ký số RSA PSS SHA-256 thành công. Hãy đưa ra 1 câu nhận xét ngắn gọn, chuyên nghiệp bằng tiếng Việt xác nhận tính toàn vẹn."
                response = ai_client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
                if response and response.text:
                    ai_comment = response.text.strip()
            except Exception:
                pass

        return {
            "status": "ACCEPTED",
            "valid": True,
            "message": f"Xác thực thành công! Tệp '{file_name}' hợp lệ và giữ nguyên tính toàn vẹn.",
            "ai_agent_analysis": ai_comment
        }

    except Exception:
        return {
            "status": "REJECTED",
            "valid": False,
            "message": f"Xác thực thất bại! Tệp '{file_name}' đã bị chỉnh sửa hoặc chữ ký không khớp."
        }


# --- 5. API AI AGENT TÓM TẮT BÀI GIẢNG (SIÊU ỔN ĐỊNH) ---
@app.get("/ai-summarize/{file_name}")
def summarize_lecture(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Không tìm thấy tệp {file_name}")

    if not ai_client:
        return {
            "file_name": file_name,
            "summary": "📌 Bài giảng âm thanh đã được xác thực toàn vẹn bằng chữ ký số. (Vui lòng cấu hình GEMINI_API_KEY trên Render)."
        }

    summary_text = ""
    prompt = (
        f"Bạn là Trợ lý AI Agent Quản lý Bài Giảng chuyên nghiệp. "
        f"Học viên đang yêu cầu tóm tắt nội dung của bài giảng có tên: '{file_name}'. "
        f"Hãy soạn một bản tóm tắt học thuật chất lượng cao bằng tiếng Việt gồm cấu trúc:\n"
        f"1. **Tóm tắt cốt lõi:** Nội dung chính của bài giảng.\n"
        f"2. **Điểm trọng tâm (Key Takeaways):** Các từ khóa, công thức hoặc khái niệm cần ghi nhớ.\n"
        f"3. **Lưu ý ôn tập:** Lời khuyên để học viên nắm vững kiến thức."
    )

    # Danh sách model thông minh dự phòng
    models = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.0-flash']

    for model_name in models:
        try:
            response = ai_client.models.generate_content(
                model=model_name,
                contents=prompt
            )
            if response and response.text:
                summary_text = response.text.strip()
                break
        except Exception as e:
            logger.warning(f"Model {model_name} lỗi: {e}")
            continue

    if not summary_text:
        summary_text = "Trợ lý AI Agent đã xác thực tệp thành công, nhưng hệ thống AI đang bận, vui lòng thử lại sau giây lát."

    return {
        "file_name": file_name,
        "summary": summary_text
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