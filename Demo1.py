import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from secretsharing import PlaintextToHexSecretSharer

def encrypt_file(file_path):
    aes_key = os.urandom(32)   # Tạo khóa AES 256-bit
    iv = os.urandom(16)        # Tạo IV 128-bit

    with open(file_path, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(file_path + ".enc", 'wb') as f:
        f.write(iv + encrypted_data)

    return aes_key

# Vòng lặp xác nhận mật khẩu
while True:
    secret = getpass.getpass("Hãy nhập password: ")
    confirm = getpass.getpass("Nhập lại password để xác nhận: ")

    if secret == confirm:
        print("Mật khẩu trùng khớp, xác nhận thành công!")
        break
    else:
        print("Mật khẩu không khớp, vui lòng nhập lại.\n")

# Chia bí mật
n = int(input("Tổng số mảnh muốn chia: "))
k = round(n * 3 / 5)
print(f"Ngưỡng khôi phục sẽ là {k}/{n}")

shares = PlaintextToHexSecretSharer.split_secret(secret, k, n)

print("Các mảnh bí mật:")
for i, s in enumerate(shares, 1):
    print(f"Mảnh {i}: {s}")

# Khôi phục bí mật
print(f"\nCần nhập ít nhất {k} mảnh để khôi phục:")
subset = []
for i in range(k):
    share = input(f"Thành viên {i+1}: ")
    subset.append(share)

recovered_secret = PlaintextToHexSecretSharer.recover_secret(subset)
print("\nBí mật khôi phục lại:", recovered_secret)
