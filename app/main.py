# app/main.py
import logging
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from google.oauth2 import id_token
from google.auth.transport import requests
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from databases import Database
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt

from .models import Base, User, RefreshToken
from .schemas import (
    UserCreate, 
    UserResponse, 
    TokenRequest, 
    Token, 
    GoogleAuthResponse
)
from .auth_utils import create_access_token, create_refresh_token
# JWT Settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/oauth_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
database = Database(DATABASE_URL)

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

# Dependency to get DB session
async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
async def startup():
    # Create database tables
    Base.metadata.create_all(bind=engine)
    await database.connect()
    logger.info("Connected to database and created tables")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logger.info("Disconnected from database")

@app.get("/")
async def root():
    return {"message": "OAuth2 API is running"}

@app.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate):
    logger.info(f"Attempting to register user with email: {user.email}")
    
    try:
        # Check if user exists
        query = User.__table__.select().where(
            (User.email == user.email) | (User.username == user.username)
        )
        existing_user = await database.fetch_one(query)
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email or username already registered"
            )

        # Create new user
        query = User.__table__.insert().values(
            email=user.email,
            username=user.username,
            hashed_password=user.password  # In production, hash the password!
        )
        user_id = await database.execute(query)
        
        # Fetch created user
        query = User.__table__.select().where(User.id == user_id)
        created_user = await database.fetch_one(query)
        logger.info(f"Successfully registered user with ID: {user_id}")
        return created_user
    
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error registering user: {str(e)}"
        )

@app.post("/auth/google", response_model=GoogleAuthResponse)
async def auth_google(token_request: TokenRequest):
    """Handle Google OAuth callback and token exchange"""
    logger.info("Received Google auth request")
    
    try:
        async with httpx.AsyncClient() as client:
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "code": token_request.code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": f"{FRONTEND_URL}/auth/google/callback",
                "grant_type": "authorization_code",
            }
            
            logger.info(f"Exchanging code for token with redirect URI: {data['redirect_uri']}")
            
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            token_data = response.json()
            
            # Verify ID token
            id_info = id_token.verify_oauth2_token(
                token_data["id_token"],
                requests.Request(),
                GOOGLE_CLIENT_ID,
                clock_skew_in_seconds=10
            )
            
            # Check if user exists
            query = User.__table__.select().where(
                (User.google_id == id_info["sub"]) | (User.email == id_info["email"])
            )
            user = await database.fetch_one(query)
            
            if not user:
                # Create new user
                username_base = id_info["email"].split("@")[0]
                username = username_base
                counter = 1
                
                while True:
                    query = User.__table__.select().where(User.username == username)
                    existing = await database.fetch_one(query)
                    if not existing:
                        break
                    username = f"{username_base}{counter}"
                    counter += 1
                
                current_time = datetime.utcnow()
                query = User.__table__.insert().values(
                    email=id_info["email"],
                    username=username,
                    google_id=id_info["sub"],
                    is_active=True,
                    created_at=current_time,
                    last_login=current_time
                )
                user_id = await database.execute(query)
                query = User.__table__.select().where(User.id == user_id)
                user = await database.fetch_one(query)
                logger.info(f"Created new user from Google OAuth: {user['email']}")
            else:
                # Update last login
                query = User.__table__.update().where(User.id == user['id']).values(
                    last_login=datetime.utcnow()
                )
                await database.execute(query)
                logger.info(f"Existing user logged in with Google: {user['email']}")

            # Create JWT tokens
            token_data = {"sub": str(user['id'])}
            access_token = create_access_token(
                data=token_data,
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            refresh_token = create_refresh_token(token_data)

            # Store refresh token in database
            query = RefreshToken.__table__.insert().values(
                user_id=user['id'],
                token=refresh_token,
                expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
            await database.execute(query)
            
            user_response = UserResponse(
                id=user['id'],
                email=user['email'],
                username=user['username'],
                google_id=user['google_id'],
                is_active=user['is_active'],
                created_at=user['created_at'],
                last_login=user['last_login']
            )
            
            return GoogleAuthResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                user=user_response
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during Google authentication: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)