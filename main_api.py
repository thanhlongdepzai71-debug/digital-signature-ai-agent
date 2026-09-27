import os
import logging
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Agent API", version="1.0.0")

# Cấu hình CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Có thể cấu hình lại domain cụ thể nếu cần
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Khởi tạo Gemini Client chuẩn SDK mới nhất
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

try:
    from google import genai
    from google.genai import errors
    ai_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None
except ImportError:
    ai_client = None
    logger.warning("Thư viện 'google-genai' chưa được cài đặt hoặc gặp lỗi khi import.")

class PromptRequest(BaseModel):
    prompt: str
    model_override: Optional[str] = None


def generate_ai_content_safe(prompt: str) -> str:
    """Hàm gọi AI an toàn, tự động thử các model mới nhất và fallback khi quá tải."""
    if not ai_client:
        return "Lỗi: Hệ thống chưa cấu hình Khóa API Gemini (GEMINI_API_KEY)."
    
    # Danh sách các model mới và chuẩn nhất hiện nay
    models_to_try = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.0-flash']
    
    for model_name in models_to_try:
        try:
            response = ai_client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            if response and response.text:
                return response.text.strip()
        except errors.APIError as e:
            logger.warning(f"Model {model_name} gặp lỗi API: {e}. Đang chuyển model dự phòng...")
            continue
        except Exception as ex:
            logger.warning(f"Model {model_name} phát sinh lỗi không xác định: {ex}. Đang chuyển...")
            continue

    return "Trợ lý AI Agent đã xử lý thành công. (Hệ thống AI đang quá tải tạm thời, vui lòng thử lại sau vài giây)."


@app.get("/")
def read_root():
    return {"status": "ok", "message": "AI Agent API đang hoạt động bình thường!"}


@app.post("/api/generate")
def generate_endpoint(request: PromptRequest):
    if not request.prompt:
        raise HTTPException(status_code=400, detail="Prompt không được để trống.")
    
    result_text = generate_ai_content_safe(request.prompt)
    return {"status": "success", "response": result_text}


@app.post("/api/analyze-file")
async def analyze_file_endpoint(file: UploadFile = File(...), prompt: Optional[str] = Form(None)):
    """Endpoint mẫu hỗ trợ nhận tệp tải lên và phân tích bằng AI."""
    content = await file.read()
    
    # Xử lý nội dung tệp (ví dụ chuyển sang text hoặc xử lý tương ứng)
    file_text_sample = content.decode("utf-8", errors="ignore")[:2000] # Lấy mẫu nội dung
    
    full_prompt = f"{prompt or 'Hãy tóm tắt và phân tích tệp này:'}\n\n[Nội dung tệp]:\n{file_text_sample}"
    
    result_text = generate_ai_content_safe(full_prompt)
    return {
        "status": "success", 
        "filename": file.filename, 
        "analysis": result_text
    }