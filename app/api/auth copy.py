from fastapi import APIRouter, Response, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from backend.app.models.models import UserAuth, Token
from passlib.context import CryptContext
from jose import JWTError, jwt
from pymongo import MongoClient
from app.utils.encryption import encrypt, decrypt  # Encryption functions
from datetime import datetime, timedelta
from backend.app.db.db import get_database
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")



# Create router
router = APIRouter()

# Initialize password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to get password hash
def get_password_hash(password):
    return pwd_context.hash(password)

# Function to create JWT token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to get current user
async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_database)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["users"].find_one({"email": encrypt(email)})
    if user is None:
        raise credentials_exception
    return user

@router.post("/register")
async def register(user: UserAuth, response: Response, db = Depends(get_database)):
    # Check if the user already exists in the database
    if db["users"].find_one({"email": encrypt(user.email)}):
        raise HTTPException(status_code=400, detail="User already registered")

    # Hash the password
    hashed_password = get_password_hash(user.password)

    # Store the user in the database with encrypted email and phone
    db["users"].insert_one({
        "email": encrypt(user.email),
        "phone": encrypt(user.phone),
        "password_hash": hashed_password,
        "date_creation": datetime.now()
    })

    response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"

    return {"msg": "User registered successfully"}

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_database)):
    user = db["users"].find_one({"email": encrypt(form_data.username)})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": decrypt(user["email"])})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me")
async def read_users_me(current_user: UserAuth = Depends(get_current_user)):
    return current_user

# Updated login function
@router.post("/login")
async def login(user: UserAuth, db = Depends(get_database)):
    db_user = db["users"].find_one({"email": encrypt(user.email)})
    if not db_user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    # Verify password with bcrypt
    if not pwd_context.verify(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    # If authentication is successful, generate a JWT
    access_token = create_access_token(data={"user_id": str(db_user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}


# Cette variable est utilisée pour extraire le token des requêtes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



# Fonction de vérification du JWT
def verify_access_token(token: str, db = Depends(get_database)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Vérifier si l'utilisateur existe
        user = db["users"].find_one({"_id": user_id})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Dépendance à utiliser dans les routes protégées
def get_current_user(token: str = Depends(oauth2_scheme)):
    return verify_access_token(token)
