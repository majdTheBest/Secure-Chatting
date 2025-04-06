import socket
import rsa  # type: ignore
from Crypto.Cipher import AES  # type: ignore
import os

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

def client_program():
    client_socket = socket.socket()
    client_socket.connect(('localhost', 12345))

    # Receive the server's public key
    server_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))

    # Encrypt the shared key with the server's public key
    shared_key = os.urandom(32)  # Generating a random shared key (symmetric key)
    encrypted_shared_key = rsa.encrypt(shared_key, server_public_key)
    
    # Send the encrypted shared key to the server
    client_socket.send(encrypted_shared_key)
    
    # Now start communication
    while True:
        message = input("Enter your message: ")
        encrypted_message = encrypt_message(message, shared_key)
        client_socket.send(encrypted_message)
        
        data = client_socket.recv(1024)
        if not data:
            break
        decrypted_message = decrypt_message(data, shared_key)
        print("Message from the server: ", decrypted_message)

    client_socket.close()

if __name__ == '__main__':
    client_program()
