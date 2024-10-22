from passlib.context import CryptContext
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import hashlib, jwt, os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# ConnectionConfig using environment variables
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS") == 'True',
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS") == 'True',
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False
)

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

# Function to generate JWT Token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    return encoded_jwt

async def send_validation_email(email: str, token: str):
    body = f"""
    <html>
        <body>
            <p>Please validate your email by clicking on the following link:</p>
            <a href="http://localhost:8000/auth/validate-email?token={token}">Validate Email</a>
        </body>
    </html>
    """
    
    message = MessageSchema(
        subject="Email Validation",
        recipients=[email],
        body=body,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)