import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# --- HÀM 1: KÝ SỐ FILE MP3 ---
def sign_mp3(mp3_path, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(mp3_path, "rb") as f:
        file_bytes = f.read()

    signature = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = mp3_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"✅ Đã ký thành công! File chữ ký tạo ra: {sig_path}")
    return sig_path


# --- HÀM 2: XÁC THỰC FILE MP3 ---
def verify_mp3(mp3_path, sig_path, public_key_path="public_key.pem"):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(mp3_path, "rb") as f:
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
        print("🎉 XÁC THỰC THÀNH CÔNG: File MP3 nguyên bản, đúng do chính chủ phát hành!")
        return True
    except Exception as e:
        print("❌ XÁC THỰC THẤT BẠI: File MP3 đã bị chỉnh sửa hoặc chữ ký không hợp lệ!")
        return False


# --- CHẠY THỬ NGHỆM ---
if __name__ == "__main__":
    # Đặt một file MP3 thực tế (ví dụ: test.mp3) cùng thư mục với file script này
    file_mp3 = "test.mp3" 
    
    print("--- ĐANG KÝ FILE MP3 ---")
    file_sig = sign_mp3(file_mp3)
    
    print("\n--- ĐANG XÁC THỰC FILE MP3 ---")
    verify_mp3(file_mp3, file_sig)