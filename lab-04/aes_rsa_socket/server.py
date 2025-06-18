from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

clients = []

# Hàm nhận đủ dữ liệu từ socket
def recv_all(sock, length):
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError('Socket closed before receiving all data')
        data += more
    return data

# Giải mã tin nhắn AES
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Xử lý client
def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    # Gửi public key của server cho client
    server_key = RSA.generate(2048)
    client_socket.send(server_key.publickey().export_key(format='PEM'))

    # Nhận chiều dài và sau đó nhận public key từ client
    key_length = int.from_bytes(client_socket.recv(4), 'big')
    data = recv_all(client_socket, key_length)
    client_received_key = RSA.import_key(data)

    # Tạo AES key
    aes_key = get_random_bytes(16)

    # Mã hóa AES key bằng public key của client
    cipher_rsa = PKCS1_OAEP.new(client_received_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    # Lưu client
    clients.append((client_socket, aes_key))

    # Nhận và in tin nhắn
    while True:
        encrypted_message = client_socket.recv(1824)
        decrypted_message = decrypt_message(aes_key, encrypted_message)
        print(f"Received from {client_address}: {decrypted_message}")

# Lắng nghe
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen()

print("Server is listening on port 12345...")

while True:
    client_socket, client_address = server_socket.accept()
    thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    thread.start()