from fastapi import APIRouter, Response, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.models.models import UserAuth, Token
from jose import JWTError, jwt
from app.utils.encryption import encrypt, decrypt  # Encryption functions
from datetime import datetime
from app.db.db import get_database
from pymongo.errors import DuplicateKeyError
from app.utils.security import get_password_hash

# Create router
router = APIRouter()

@router.post("/register")
async def register(user: UserAuth, response: Response, db = Depends(get_database)):
    # Check if the user already exists in the database
    if db["users"].find_one({"email": encrypt(user.email)}):
        raise HTTPException(status_code=400, detail="User already registered")

    # Hash the password
    hashed_password = get_password_hash(user.password)

    try:
        # Store the user in the database with encrypted email and phone
        result = db["users"].insert_one({
            "email": user.email,    # ADD encrypt
            "phone": user.countryCode + user.phone,  # ADD encrypt
            "password_hash": user.password, #hashed_password,
            "date_creation": datetime.now()
        })
        # Log the result of the insertion
        print(f"Inserted user with _id: {result.inserted_id}")
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email already exists")
    

    return {"msg": "User registered successfully"}





@router.get("/first-user")
async def get_first_user(db = Depends(get_database)):
    first_user = db["users"].find_one()
    print(first_user)
    if not first_user:
        raise HTTPException(status_code=404, detail="No users found")
    
    # Convert ObjectId to string for JSON serialization
    if "_id" in first_user:
        first_user["_id"] = str(first_user["_id"])

    return first_user

