import socket
import rsa
from Crypto.Cipher import AES
import os
import threading

# Generate RSA keys (Asymmetric Encryption)
public_key, private_key = rsa.newkeys(512)

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + tag + ciphertext

def decrypt_message(ciphertext, key):
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def handle_client(conn, addr):
    # Send public key to client
    conn.send(public_key.save_pkcs1())

    # Receive encrypted shared key from client
    encrypted_key = conn.recv(1024)
    shared_key = rsa.decrypt(encrypted_key, private_key)

    # Communicate securely using symmetric encryption
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Encrypted message from client {addr}: ", data)
        decrypted_message = decrypt_message(data, shared_key)
        print(f"Decrypted message: ", decrypted_message)

        response = input("Enter your message to the client: ")
        encrypted_response = encrypt_message(response, shared_key)
        conn.send(encrypted_response)

    conn.close()

def server_program():
    server_socket = socket.socket()
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)  # Allow up to 5 clients to queue up for connection

    print("Server is waiting for client connections...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Client connected from {addr}")

        # Start a new thread to handle the client's requests
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

if __name__ == '__main__':
    server_program()
