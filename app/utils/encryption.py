from cryptography.fernet import Fernet

# Exemple : Générer et stocker cette clé de manière sécurisée
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt(data: str) -> str:
    return cipher_suite.decrypt(data.encode()).decode()
