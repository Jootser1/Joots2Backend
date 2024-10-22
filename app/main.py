from fastapi import FastAPI, Response, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.api.auth import router as auth_router
from app.api.api_users import router as users_router
from app.db.db import get_database


app = FastAPI()

# Configuration CORS sécurisée
origins = [
    "https://joots.com",
    "http://joots.com",  # URL de ton frontend en production
    "http://localhost:8081",
    "http://localhost"  # Pour le développement local avec React Native
]

# Ajouter le middleware CORS à FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Liste des origines autorisées
    allow_credentials=True,  # Autoriser l'envoi des cookies et des en-têtes d'authentification
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Méthodes HTTP autorisées
    allow_headers=["Authorization", "Content-Type"],  # En-têtes autorisés
)


# Include routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router, prefix="/users", tags=["users"])  # Include the users router


@app.get("/")
def read_root():
    return {"msg": "Welcome to the FastAPI backend!"}

# Simple test route to verify CORS headers
@app.get("/test-cors")
async def test_cors(response: Response):
    response.headers["Custom-Header"] = "Value"
    return {"message": "CORS headers should be set"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)