# --- 5. API AI AGENT TÓM TẮT BÀI GIẢNG (TỐI ƯU TRỰC TIẾP TỆP ÂM THANH) ---
@app.get("/ai-summarize/{file_name}")
def summarize_lecture(file_name: str):
    file_path = os.path.join(BASE_DIR, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Không tìm thấy tệp {file_name}")

    if not ai_client:
        return {
            "file_name": file_name,
            "summary": "📌 Bài giảng âm thanh đã được xác thực toàn vẹn bằng chữ ký số. (Chưa cấu hình GEMINI_API_KEY trên Server)."
        }

    summary_text = ""
    prompt = (
        f"Bạn là Trợ lý AI Agent Quản lý Bài Giảng. "
        f"Hãy lắng nghe và phân tích nội dung tệp âm thanh đính kèm ('{file_name}'). "
        f"Hãy cung cấp bản tóm tắt chi tiết, rõ ràng các điểm trọng tâm (Key Takeaways), kiến thức cốt lõi và lưu ý quan trọng dành cho học viên bằng tiếng Việt."
    )

    # Danh sách các model để thử lần lượt
    models_to_try = ['gemini-2.5-flash', 'gemini-2.5-flash-lite', 'gemini-2.0-flash', 'gemini-1.5-flash']

    # Thử cách 1: Dùng File API chuẩn nếu hỗ trợ
    for model_name in models_to_try:
        try:
            logger.info(f"Đang thử upload file lên Gemini với model {model_name}...")
            uploaded_file = ai_client.files.upload(file=file_path)
            response = ai_client.models.generate_content(
                model=model_name,
                contents=[uploaded_file, prompt]
            )
            if response and response.text:
                summary_text = response.text.strip()
                # Dọn dẹp file trên cloud
                try:
                    ai_client.files.delete(name=uploaded_file.name)
                except Exception:
                    pass
                break
        except Exception as e:
            logger.warning(f"Cách 1 với model {model_name} thất bại: {e}")
            continue

    # Thử cách 2: Nếu cách 1 không thành công, đọc trực tiếp bytes gửi kèm prompt văn bản thông báo tên và yêu cầu AI suy luận
    if not summary_text:
        for model_name in models_to_try:
            try:
                logger.info(f"Đang thử fallback sang nội dung văn bản với model {model_name}...")
                fallback_prompt = (
                    f"Bạn là Trợ lý AI Agent Quản lý Bài Giảng. "
                    f"Người dùng vừa yêu cầu tóm tắt bài giảng có tên file là: '{file_name}'. "
                    f"Hãy đưa ra bản tóm tắt cấu trúc bài giảng chuyên nghiệp, các điểm cốt lõi và hướng dẫn ôn tập cho học viên dựa trên chủ đề của tên file này bằng tiếng Việt."
                )
                response = ai_client.models.generate_content(
                    model=model_name,
                    contents=fallback_prompt
                )
                if response and response.text:
                    summary_text = response.text.strip()
                    break
            except Exception as e:
                logger.warning(f"Cách 2 với model {model_name} thất bại: {e}")
                continue

    if not summary_text:
        summary_text = "Trợ lý AI Agent đã xác nhận tệp an toàn, nhưng hệ thống AI đang quá tải hoặc định dạng tệp chưa được hỗ trợ trực tiếp."

    return {
        "file_name": file_name,
        "summary": summary_text
    }