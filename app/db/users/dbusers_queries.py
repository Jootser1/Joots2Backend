from app.db.db import get_database
from fastapi import Depends

def count_validated_users(db=Depends(get_database)):
    count = db.users.count_documents({'is_user_validated': True})
    print(count)
    return count

if __name__ == "__main__":
    db = get_database()
    # Appelez la fonction avec la base de données et imprimez le résultat
    print(f"Number of validated users: {count_validated_users(db)}")