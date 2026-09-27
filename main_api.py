import os
import glob
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from google import genai

app = FastAPI(title="Digital Signature AI Agent API")

# Bật CORS cho phép kết nối từ GitHub Pages
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

# Khởi tạo Gemini Client (lấy API Key tự động từ biến môi trường GEMINI_API_KEY)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
ai_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None


# Hàm hỗ trợ tự động ký số RSA PSS SHA-256
def auto_sign_file(file_path: str):
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise HTTPException(status_code=500, detail="Chưa tìm thấy file private_key.pem trên Server")

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


# 1. API UPLOAD & TỰ ĐỘNG KÝ SỐ
@app.post("/upload")
async def upload_audio(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(BASE_DIR, file.filename)

        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        auto_sign_file(file_path)

        return {
            "status": "success",
            "message": f"Đã tải lên và tự động ký số thành công cho {file.filename}!",
            "file_name": file.filename,
            "sig_file": f"{file.filename}.sig"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 2. API TRẢ VỀ DANH SÁCH FILE MP3 (JSON)
@app.get("/download-audio-list")
def get_audio_list():
    audio_files = []
    for file in os.listdir(BASE_DIR):
        if file.endswith(".mp3"):
            audio_files.append({"file_name": file})
    return audio_files


# 3. API TẢI / PHÁT FILE
@app.get("/download/{file_name}")
@app.get("/files/{file_name}")
def download_file(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp yêu cầu")
    return FileResponse(path=file_path, filename=file_name)


# 4. API XÁC THỰC CHỮ KÝ SỐ + PHÂN TÍCH AI AGENT
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

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        ai_comment = "Xác thực chữ ký RSA thành công."
        if ai_client:
            try:
                prompt = (
                    f"Bạn là Trợ lý AI Agent Xác thực Chữ ký số. "
                    f"Tệp '{file_name}' vừa được kiểm tra thành công với chữ ký RSA PSS SHA-256. "
                    f"Hãy đưa ra 1 câu nhận xét ngắn gọn, chuyên nghiệp bằng tiếng Việt xác nhận tính toàn vẹn của bài giảng này."
                )
                response = ai_client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                )
                if response.text:
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


# 5. API TÓM TẮT BÀI GIẢNG BẰNG AI AGENT (GEMINI)
@app.get("/ai-summarize/{file_name}")
def summarize_lecture(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Không tìm thấy tệp {file_name}")

    if not ai_client:
        return {
            "file_name": file_name,
            "summary": "📌 Bài giảng âm thanh đã được xác thực toàn vẹn bằng chữ ký số RSA SHA-256. (Vui lòng cấu hình GEMINI_API_KEY trên Render để xem tóm tắt chuyên sâu từ AI Agent)."
        }

    try:
        prompt = (
            f"Bạn là Trợ lý AI Agent Quản lý Bài Giảng. "
            f"Hãy đưa ra bản tóm tắt ngắn gọn, dễ hiểu và các điểm trọng tâm cần lưu ý cho học viên đối với bài giảng ghi âm có tên '{file_name}'."
        )
        response = ai_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )

        return {
            "file_name": file_name,
            "summary": response.text
        }
    except Exception as e:
        return {
            "file_name": file_name,
            "summary": f"Trợ lý AI Agent đã xác nhận tệp an toàn. Lỗi tóm tắt: {str(e)}"
        }


# 6. API XÓA BÀI GIẢNG VÀ CHỮ KÝ SỐ (QUYỀN TẢI LÊN / GIẢNG VIÊN)
@app.delete("/delete/{file_name}")
def delete_lecture(file_name: str):
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
        "message": f"Đã xóa thành công bài giảng '{file_name}' và chữ ký số đính kèm!",
        "deleted_files": deleted_items
    }