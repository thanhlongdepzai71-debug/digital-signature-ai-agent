from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def sign_pdf(pdf_path, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(pdf_path, "rb") as f:
        file_bytes = f.read()

    signature = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = pdf_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"✅ Đã ký file PDF thành công: {sig_path}")
    return sig_path

def verify_pdf(pdf_path, sig_path, public_key_path="public_key.pem"):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(pdf_path, "rb") as f:
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
        print("🎉 XÁC THỰC PDF THÀNH CÔNG: Tệp PDF nguyên bản!")
        return True
    except Exception:
        print("❌ XÁC THỰC THẤT BẠI: Tệp PDF đã bị chỉnh sửa!")
        return False

if __name__ == "__main__":
    # Chuẩn bị 1 file test.pdf ở Desktop để test
    file_pdf = "test.pdf"
    sig = sign_pdf(file_pdf)
    verify_pdf(file_pdf, sig)