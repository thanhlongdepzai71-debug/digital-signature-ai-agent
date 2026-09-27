import os
import json
from fastapi import FastAPI
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

app = FastAPI(title="Digital Signature Verification API for AI Agent")

# Danh sách tệp ghi âm mô phỏng lưu trên Server
AUDIO_RECORDS_DB = [
    {
        "id": 1,
        "student_id": "SV001",
        "file_name": "test.mp3",
        "signature_file": "test.mp3.sig",
        "status": "ACCEPTED",
        "timestamp": "2026-09-27 10:30:00",
        "download_url": "http://127.0.0.1:8000/files/test.mp3"
    },
    {
        "id": 2,
        "student_id": "SV002",
        "file_name": "ghi_am_gia_mao.mp3",
        "signature_file": "ghi_am_gia_mao.mp3.sig",
        "status": "REJECTED",
        "timestamp": "2026-09-27 10:32:15",
        "download_url": "http://127.0.0.1:8000/files/ghi_am_gia_mao.mp3"
    }
]

# Hàm kiểm tra chữ ký số RSA
def verify_signature(file_path: str, sig_path: str, public_key_path="public_key.pem") -> bool:
    if not os.path.exists(file_path) or not os.path.exists(sig_path):
        return False

    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(file_path, "rb") as f:
        file_bytes = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

@app.post("/verify")
def verify_file(file_name: str):
    sig_name = f"{file_name}.sig"
    is_valid = verify_signature(file_name, sig_name)
    
    if is_valid:
        return {
            "status": "ACCEPTED",
            "message": f"Chữ ký số hợp lệ cho tệp {file_name}.",
            "file": file_name
        }
    else:
        return {
            "status": "REJECTED",
            "message": f"Chữ ký số KHÔNG hợp lệ hoặc thiếu tệp {sig_name}.",
            "file": file_name
        }

# Endpoint xuất file JSON danh sách ghi âm (Ý của Thầy)
@app.get("/download-audio-list")
def download_audio_list():
    json_path = "recorded_files_list.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(AUDIO_RECORDS_DB, f, ensure_ascii=False, indent=4)
        
    return FileResponse(
        path=json_path, 
        filename="recorded_files_list.json", 
        media_type="application/json"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)