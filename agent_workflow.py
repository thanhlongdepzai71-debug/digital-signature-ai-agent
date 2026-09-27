import requests
import json

# Tool 1: Xác thực chữ ký số file bài nộp
def verify_submission_tool(file_name: str) -> dict:
    url = "http://127.0.0.1:8000/verify"
    params = {"file_name": file_name}
    try:
        response = requests.post(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "message": f"Lỗi Server (Mã {response.status_code})"}
    except Exception as e:
        return {"status": "error", "message": f"Không thể kết nối tới API: {e}"}

# Tool 2: Tải danh sách file ghi âm dạng JSON từ Server
def get_recorded_audio_list():
    url = "http://127.0.0.1:8000/download-audio-list"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open("downloaded_audio_list.json", "wb") as f:
                f.write(response.content)
            return response.json()
        else:
            return {"status": "error", "message": "Không thể tải danh sách JSON"}
    except Exception as e:
        return {"status": "error", "message": f"Lỗi kết nối: {e}"}

if __name__ == "__main__":
    print("--- KỊCH BẢN 1: NỘP BÀI HỢP LỆ ---")
    res1 = verify_submission_tool("test.pdf")
    print(json.dumps(res1, ensure_ascii=False, indent=2))
    
    print("\n--- KỊCH BẢN 2: NỘP BÀI GIẢ MẠO ---")
    res2 = verify_submission_tool("bai_tap_gia_mao.pdf")
    print(json.dumps(res2, ensure_ascii=False, indent=2))

    print("\n--- KỊCH BẢN 3: TẢI DANH SÁCH FILE GHI ÂM (JSON) TỪ SERVER ---")
    print("🤖 [AI Agent]: Đang gửi yêu cầu lấy danh sách tệp ghi âm...")
    audio_list = get_recorded_audio_list()
    print("✅ Đã tải file JSON danh sách ghi âm về máy thành công:")
    print(json.dumps(audio_list, ensure_ascii=False, indent=2))