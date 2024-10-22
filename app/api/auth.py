from fastapi import APIRouter, Response, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.models.models import UserAuth, Token, LoginResponse, LoginRequest
from jose import JWTError, jwt
from app.utils.encryption import encrypt, decrypt  # Encryption functions
from datetime import datetime, timedelta
from app.db.db import get_database
from pymongo.errors import DuplicateKeyError
from app.utils.security import get_password_hash, hash_email, create_access_token, verify_password, send_validation_email
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Create router
router = APIRouter()



#USER REGISTRATION
@router.post("/register")
async def register(user: UserAuth, response: Response, db=Depends(get_database)):

    hashed_password = get_password_hash(user.password)
    hashed_email = hash_email(user.email)

    # Check if the user already exists in the database
    if db["users"].find_one({"email": hashed_email}):
        raise HTTPException(status_code=400, detail="User already registered")

    try:
        # Store the user in the database with encrypted email and phone
        result = db["users"].insert_one(
            {
                "email": hashed_email,  
                "phone": encrypt(user.countryCode + user.phone),  
                "password_hash": hashed_password,
                "Jootserid" : "Jootser3",
                "is_user_validated" : False,
                "date_creation": datetime.now(),
            }
        )
        token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")))
        token = create_access_token(data={"sub": user.email}, expires_delta=token_expires)
        print(token)
        await send_validation_email(user.email, token)
        
        # Log the result of the insertion
        print(f"Inserted user with _id: {result.inserted_id}")
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email already exists")

    return {"msg": "User registered successfully"}


# EMAIL VALIDATION AFTER REGISTRATION
@router.get("/validate-email")
async def validate_email(token: str, db=Depends(get_database)):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        email = payload.get("sub")
        print(email)
        if email is None:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

    hashed_email = hash_email(email)
    result = db["users"].update_one(
        {"email": hashed_email},
        {"$set": {"is_user_validated": True}}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="User not found or already validated")

    return {"msg": "Email validated successfully"}


# USER AUTHENTIFICATION
def authenticate_user(username: str, password: str, db=Depends(get_database)):
    user = db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_database)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}