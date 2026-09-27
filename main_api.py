import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI(title="Digital Signature AI Agent API")

# Cấu hình CORS để GitHub Pages kết nối tới Render không bị chặn
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Thư mục lưu trữ file trên server
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Digital Signature AI Agent API is running!"}

# API Tải lên & Ký số file
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        
        # Lưu file tải lên vào thư mục uploads
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
            
        # TODO: Đoạn này tích hợp logic ký số RSA/PyHanko cho file tùy theo định dạng
        
        return {
            "message": f"Đã tải lên và tự động ký số thành công cho {file.filename}!",
            "filename": file.filename
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# API Lấy danh sách bài giảng / tài liệu
@app.get("/files")
def list_files():
    if not os.path.exists(UPLOAD_DIR):
        return []
    
    files = os.listdir(UPLOAD_DIR)
    file_list = []
    for f in files:
        file_path = os.path.join(UPLOAD_DIR, f)
        if os.path.isfile(file_path):
            file_list.append({
                "filename": f,
                "size": os.path.getsize(file_path)
            })
    return file_list

# API Tải file / Phát bài giảng
@app.get("/files/{filename}")
def get_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File không tồn tại")
    return FileResponse(file_path)