from passlib.context import CryptContext
import hashlib

# Initialize password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to get password hash
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Function to verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Function to hash email using SHA-256
def hash_email(email: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(email.encode('utf-8'))
    return sha256.hexdigest()