import configparser
import datetime
from typing import List, Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from .models import Base, AdminRegistration, Book, CustomerRegistration, LibrarianRegistration, TokenData, User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
#from models import Base
import os
from dotenv import load_dotenv
import secrets
from jose import JWTError, jwt


# Load values from alembic.ini
config = configparser.ConfigParser()
config.read('alembic.ini')

# Get the value of sqlalchemy.url
database_url = config.get('alembic', 'sqlalchemy.url')

engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Authenticate user
def authenticate_user(db, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return False
    return user


# Create access token
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Login endpoint
@app.post("/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.email, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.email}, 
        expires_delta=datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Register endpoint
@app.post("/register", response_model=User)
async def register_user(user_data: CustomerRegistration):
    db = SessionLocal()
    # Check if the email is already registered
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Email already registered")

    # Create a new user
    new_user = User(
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        email=user_data.email,
        password=pwd_context.hash(user_data.password),
        role=user_data.role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    # TODO: replace later with: return {"redirect_url": "/login"}
    return new_user


@app.post("/register/admin", response_model=User)
async def register_admin(admin_data: AdminRegistration):
    db = SessionLocal()
    # Check if the email is already registered
    if db.query(User).filter(User.email == admin_data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Email already registered")
    

    # Create a new admin user
    new_user = User(
        first_name=admin_data.first_name,
        last_name=admin_data.last_name,
        email=admin_data.email,
        password=pwd_context.hash(admin_data.password),
        role="admin"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return new_user


@app.post("/register/librarian", response_model=User)
async def register_librarian(librarian_data: LibrarianRegistration):
    db = SessionLocal()
    # Check if the email is already registered
    if db.query(User).filter(User.email == librarian_data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Email already registered")

    # Create a new librarian user
    new_user = User(
        first_name=librarian_data.first_name,
        last_name=librarian_data.last_name,
        email=librarian_data.email,
        password=pwd_context.hash(librarian_data.password),
        role="librarian"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return new_user


# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = TokenData(email=email)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch the user from the database using the email obtained from the token
    user = SessionLocal().query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# Get the borrowed books of the current user
@app.get("/profile", response_model=List[Book])
async def get_client_profile(
    current_user: User = Depends(get_current_user), db: Session = Depends(SessionLocal)
    ):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not authenticated"
            )

    # Query the database for the borrowed books of the user
    borrowed_books = db.query(Book).filter(Book.borrower_id == current_user.id).all()
    
    return borrowed_books

# Admin profile endpoint
@app.get("/admin/profile", response_model=User)
async def get_admin_profile(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                            detail="User is not an admin")

    return current_user

# Librarian profile endpoint
@app.get("/librarian/profile", response_model=User)
async def get_librarian_profile(current_user: User = Depends(get_current_user)):
    if current_user.role != "librarian":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                            detail="User is not a librarian")

    return current_user


@app.get("/")
async def read_root():
    return {"message": "Welcome to the bookstore API!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
