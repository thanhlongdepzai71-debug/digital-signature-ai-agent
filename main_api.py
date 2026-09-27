# --- 5. API AI AGENT TÓM TẮT BÀI GIẢNG (ĐÃ NÂNG CẤP ĐỌC FILE) ---
@app.get("/ai-summarize/{file_name}")
def summarize_lecture(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Không tìm thấy tệp {file_name}")

    if not ai_client:
        return {
            "file_name": file_name,
            "summary": "📌 Bài giảng đã được xác thực toàn vẹn bằng chữ ký số. (Chưa cấu hình GEMINI_API_KEY trên server)."
        }

    try:
        # Bước 1: Upload file trực tiếp lên Gemini File API để AI xử lý tệp âm thanh/tài liệu lớn
        logger.info(f"Đang tải file {file_name} lên Gemini File API...")
        uploaded_file = ai_client.files.upload(file=file_path)

        prompt = (
            f"Bạn là Trợ lý AI Agent Quản lý Bài Giảng. "
            f"Hãy lắng nghe/đọc tệp bài giảng vừa đính kèm ('{file_name}') và cung cấp bản tóm tắt chi tiết, "
            f"rõ ràng các điểm trọng tâm (Key Takeaways), kiến thức cốt lõi và lưu ý quan trọng dành cho học viên bằng tiếng Việt."
        )

        # Bước 2: Gọi AI tạo nội dung dựa trên file thực tế
        models_to_try = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.0-flash']
        summary_text = ""

        for model_name in models_to_try:
            try:
                response = ai_client.models.generate_content(
                    model=model_name,
                    contents=[uploaded_file, prompt]
                )
                if response and response.text:
                    summary_text = response.text.strip()
                    break
            except Exception as e:
                logger.warning(f"Model {model_name} gặp lỗi khi xử lý tệp: {e}. Thử model khác...")
                continue

        # Bước 3: Dọn dẹp file trên cloud sau khi xử lý xong (tùy chọn nhưng khuyến khích)
        try:
            ai_client.files.delete(name=uploaded_file.name)
        except Exception:
            pass

        if not summary_text:
            summary_text = "Trợ lý AI Agent đã xác nhận tệp an toàn, nhưng hiện tại không thể phân tích nội dung âm thanh của tệp này."

        return {
            "file_name": file_name,
            "summary": summary_text
        }

    except Exception as e:
        return {
            "file_name": file_name,
            "summary": f"Lỗi khi AI Agent phân tích tệp âm thanh: {str(e)}"
        }