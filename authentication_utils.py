import hashlib
import socket
import json


# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function for client registration
def register(username, password):
    hashed_password = hash_password(password)
    request_data = {
        "action": "register",
        "username": username,
        "password": password,
        "hashed_password": hashed_password,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(("localhost", 43445))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)
        return response


# Function for client login
def login(username, password):
    request_data = {"action": "login", "username": username, "password": password}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(("localhost", 43445))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)
        return response
