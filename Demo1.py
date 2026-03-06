import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from secretsharing import PlaintextToHexSecretSharer # Thư viện Shamir
from secretsharing import PlaintextToHexSecretSharer

def encrypt_file(file_path):
    # 1. Tạo một khóa AES 256-bit ngẫu nhiên (32 bytes)
    # Đây chính là "Chìa khóa gốc" cần được bảo vệ
    aes_key = os.urandom(32) 
    
    # 2. Tạo vector khởi tạo (IV) để đảm bảo cùng 1 file mã hóa 2 lần sẽ ra 2 kết quả khác nhau
    iv = os.urandom(16)
    
    # 3. Đọc dữ liệu file gốc
    with open(file_path, 'rb') as f:
        data = f.read()

    # 4. Thiết lập thuật toán AES chế độ CFB (không cần padding dữ liệu)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # 5. Lưu file đã mã hóa xuống server (.enc)
    with open(file_path + ".enc", 'wb') as f:
        f.write(iv + encrypted_data) # Lưu IV ở đầu file để sau này giải mã
        
    return aes_key # Trả về khóa để đem đi chia nhỏ bằng Shamir

# Nhập bí mật
secret = input("Nhập bí mật cần chia: ")

# Nhập số mảnh
n = int(input("Tổng số mảnh muốn chia: "))

# Tính ngưỡng theo 3/5 số mảnh
k = round(n * 3 / 5)
print(f"Ngưỡng khôi phục sẽ là {k}/{n}")

# Chia bí mật
shares = PlaintextToHexSecretSharer.split_secret(secret, k, n)

print("\nCác mảnh bí mật:")
for i, s in enumerate(shares, 1):
    print(f"Mảnh {i}: {s}")

# --- Khôi phục ---
print(f"\nNhập ít nhất {k} mảnh để khôi phục:")
subset = []
for i in range(k):
    share = input(f"Nhập mảnh {i+1}: ")
    subset.append(share)

recovered_secret = PlaintextToHexSecretSharer.recover_secret(subset)
print("\nBí mật khôi phục lại:", recovered_secret)
