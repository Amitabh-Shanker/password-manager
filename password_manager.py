# password_manager.py  (core)
import os, json, hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

STORAGE_FILE = "passwords.json"

def generate_rsa_keys():
    # generate keys (call once)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("private.pem","wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open("public.pem","wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Generated private.pem and public.pem")

def load_keys():
    with open("private.pem","rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open("public.pem","rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

def load_storage():
    """Load stored passwords from passwords.json, or return empty dict if file is empty or invalid"""
    if not os.path.exists("passwords.json"):
        return {}

    try:
        with open("passwords.json", "r") as f:
            data = f.read().strip()
            if not data:  # if file is empty
                return {}
            return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return {}


def save_storage(data):
    with open(STORAGE_FILE,"w") as f:
        json.dump(data, f, indent=2)

def add_password(service, password, public_key):
    service_hash = hashlib.sha256(service.encode()).hexdigest()
    fernet_key = Fernet.generate_key()
    fer = Fernet(fernet_key)
    encrypted_password = fer.encrypt(password.encode()).decode()
    encrypted_fernet_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    data = load_storage()
    data[service_hash] = {"key": encrypted_fernet_key.hex(), "password": encrypted_password}
    save_storage(data)
    print("Stored password for", service)

def view_password(service, private_key):
    service_hash = hashlib.sha256(service.encode()).hexdigest()
    data = load_storage()
    if service_hash not in data:
        print("No entry for", service)
        return
    entry = data[service_hash]
    encrypted_fernet_key = bytes.fromhex(entry["key"])
    fernet_key = private_key.decrypt(
        encrypted_fernet_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    fer = Fernet(fernet_key)
    decrypted_password = fer.decrypt(entry["password"].encode()).decode()
    print("Service:", service, "| Password:", decrypted_password)

if __name__ == "__main__":
    if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
        generate_rsa_keys()
    priv, pub = load_keys()
    while True:
        mode = input("add/view/quit: ").strip().lower()
        if mode == "quit":
            break
        elif mode == "add":
            s = input("Service: ").strip()
            p = input("Password: ").strip()
            add_password(s, p, pub)
        elif mode == "view":
            s = input("Service: ").strip()
            view_password(s, priv)
        else:
            print("Invalid option")
