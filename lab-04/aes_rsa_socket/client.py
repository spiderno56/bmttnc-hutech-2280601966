from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Kết nối tới server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Tạo cặp khóa RSA
client_key = RSA.generate(2048)

# Nhận public key từ server
server_public_key = RSA.import_key(client_socket.recv(2048))

# Gửi public key của client kèm độ dài
public_key_bytes = client_key.publickey().export_key(format='PEM')
client_socket.send(len(public_key_bytes).to_bytes(4, 'big'))
client_socket.send(public_key_bytes)

# Nhận và giải mã AES key từ server
encrypted_aes_key = client_socket.recv(2048)
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# Mã hóa tin nhắn AES
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Giải mã tin nhắn AES
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Nhận tin nhắn từ server
def receive_messages():
    while True:
        encrypted_message = client_socket.recv(1024)
        decrypted_message = decrypt_message(aes_key, encrypted_message)
        print("Received:", decrypted_message)

# Bắt đầu nhận tin nhắn từ server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

# Gửi tin nhắn tới server
while True:
    message = input("Enter message ('exit' to quit): ")
    encrypted_message = encrypt_message(aes_key, message)
    client_socket.send(encrypted_message)
    if message == "exit":
        break

client_socket.close()