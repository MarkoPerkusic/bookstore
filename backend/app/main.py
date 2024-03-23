from fastapi import FastAPI, HTTPException, status
from passlib.context import CryptContext
from backend.app.models import CustomerRegistration
from models import CustomerRegistration, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Register endpoint
@app.post("/register", response_model=User)
async def register_user(user_data: CustomerRegistration):
    db = SessionLocal()
    # Check if the email is already registered
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Email already registered")
    
    # Hash the user's password
    hashed_password = pwd_context.hash(user_data.password)

    # Create a new user
    new_user = User(
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        email=user_data.email,
        password=hashed_password,
        role=user_data.role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    # TODO: replace later with: return {"redirect_url": "/login"}
    return new_user

@app.get("/")
async def read_root():
    return {"message": "Welcome to the bookstore API!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
