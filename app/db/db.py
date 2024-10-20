from pymongo import MongoClient
from dotenv import dotenv_values, load_dotenv
import os

# Access the environment variables
load_dotenv()
mongo_url = os.getenv("MONGO_URL")
db_name = os.getenv("DB_NAME")
print(f"Using database {db_name} at the adress {mongo_url} ")

# Connect to MongoDB
client = MongoClient(mongo_url)
db = client[str(db_name)]


# Fonction de dépendance pour injecter la base de données dans les routes FastAPI
def get_database():
    return db
