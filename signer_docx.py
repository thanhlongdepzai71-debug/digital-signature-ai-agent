from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def sign_docx(docx_path, private_key_path="private_key.pem"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(docx_path, "rb") as f:
        file_bytes = f.read()

    signature = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = docx_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"✅ Đã ký file DOCX thành công: {sig_path}")
    return sig_path

def verify_docx(docx_path, sig_path, public_key_path="public_key.pem"):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(docx_path, "rb") as f:
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
        print("🎉 XÁC THỰC DOCX THÀNH CÔNG: Tệp Word nguyên bản!")
        return True
    except Exception:
        print("❌ XÁC THỰC THẤT BẠI: Tệp Word đã bị chỉnh sửa!")
        return False

if __name__ == "__main__":
    # Chuẩn bị 1 file test.docx ở Desktop để test
    file_docx = "test.docx"
    sig = sign_docx(file_docx)
    verify_docx(file_docx, sig)