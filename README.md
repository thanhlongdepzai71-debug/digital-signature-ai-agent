\# 🔏 Hệ Thống Xác Thực Chữ Ký Số Tệp Đa Định Dạng Tích Hợp AI Agent



Hệ thống xác thực tính toàn vẹn tài liệu (PDF, DOCX, MP3) sử dụng thuật toán mã hóa bất đối xứng \*\*RSA (SHA-256 với PSS Padding)\*\* kết hợp với API Backend (\*\*FastAPI\*\*) và luồng xử lý tự động của \*\*AI Agent\*\*.



---



\## 📐 Kiến Trúc Hệ Thống



1\. \*\*Khóa mã hóa RSA (2048-bit):\*\* Tạo cặp khóa Public/Private Key (`private\_key.pem`, `public\_key.pem`).

2\. \*\*Ký số tách rời (Detached Signature):\*\* Tạo file `.sig` độc lập cho từng loại tệp (`.pdf`, `.docx`, `.mp3`).

3\. \*\*API Service (`main\_api.py`):\*\* Cung cấp endpoint `/verify` nhận tên file và tự động đối chiếu chữ ký số `.sig` tương ứng.

4\. \*\*AI Agent Workflow (`agent\_workflow.py`):\*\* Đóng vai trò trợ lý chấm bài tự động, tự gọi Tool kiểm tra chữ ký trước khi quyết định chấm điểm (`ACCEPTED`) hay từ chối (`REJECTED`).



---



\## 🛠️ Cấu Trúc Thư Mục Dự Án
digital-signature-ai-agent/
│
├── main_api.py            # FastAPI Server (Cổng 8000)
├── agent_workflow.py      # AI Agent Workflow test các kịch bản
├── requirements.txt       # Danh sách thư viện phụ thuộc
├── README.md              # Tài liệu hướng dẫn dự án
├── private_key.pem        # RSA Private Key (dùng để ký)
├── public_key.pem         # RSA Public Key (dùng để xác thực)
│
├── test.pdf               # File test PDF
├── test.pdf.sig           # Chữ ký số file PDF
├── test.docx              # File test DOCX
├── test.docx.sig          # Chữ ký số file DOCX
├── test.mp3               # File test MP3
└── test.mp3.sig           # Chữ ký số file MP3

