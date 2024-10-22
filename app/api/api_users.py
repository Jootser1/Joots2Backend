from fastapi import APIRouter, Response, Depends, HTTPException, status
from app.db.db import get_database
from app.db.users.dbusers_queries import count_validated_users

# Create router
router = APIRouter()

@router.get("/nb-user")
async def get_nb_users(db=Depends(get_database)):
    nb_users = count_validated_users(db)
    if not nb_users:
        raise HTTPException(status_code=404, detail="No users found")

    # Convert ObjectId to string for JSON serialization
    if nb_users:
        return nb_users