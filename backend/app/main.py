import configparser
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from .models import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import secrets
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware


# Load values from alembic.ini
config = configparser.ConfigParser()
config.read('alembic.ini')

# Get the value of sqlalchemy.url
database_url = config.get('alembic', 'sqlalchemy.url')

engine = create_engine(database_url, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"])

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
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Login endpoint
@app.post("/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):

    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.email}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, 
            "token_type": "bearer", 
            "role": user.role, 
            "name": user.first_name,}


# Register endpoint
@app.post("/register", response_model=UserModel)
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
        password=pwd_context.hash(user_data.password.get_secret_value()),
        role="customer"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return JSONResponse(content={"message": "User registration successful"}, 
                        status_code=status.HTTP_200_OK)


@app.post("/register/admin", response_model=UserModel)
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
        password=pwd_context.hash(admin_data.password.get_secret_value()),
        role="admin"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()

    return new_user


@app.post("/register/librarian", response_model=UserModel)
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
        password=pwd_context.hash(librarian_data.password.get_secret_value()),
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
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials due to: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    db = SessionLocal()

    # Fetch the user from the database using the email obtained from the token
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# Get the borrowed books of the current user
@app.get("/profile", response_model=List[ShowBooks])
async def get_client_profile(
    current_user: User = Depends(get_current_user)
   ):
    
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="User not authenticated"
        )
    
    db = SessionLocal()

    # Query the database for the borrowed books of the user
    borrowed_books = db.query(Book).filter(Book.borrower_id == current_user.id).all()
    
    return borrowed_books

# Admin profile endpoint
@app.get("/admin/profile", response_model=UserModel)
async def get_admin_profile(current_user: User = Depends(get_current_user)):

    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                            detail="User is not an admin")

    return current_user

# Librarian profile endpoint
@app.get("/librarian/clients", response_model=List[UserModel])
async def get_librarian_profile(current_user: User = Depends(get_current_user)):

    print(f"{current_user.role}")

    if current_user.role not in ["librarian", "admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                            detail="User is not a librarian")
    
    db = SessionLocal()

    clients = db.query(User).filter(User.role == "customer").all()
    
    clients_data = [{"id": client.id, "first_name": client.first_name, "last_name": client.last_name, "email": client.email, "role": client.role} for client in clients]
    print(f"{clients_data}")

    return clients


@app.get("/")
async def read_root():
    return {"message": "Welcome to the bookstore API!"}

@app.put("/users/{user_id}/role", response_model=UserModel)
async def change_user_role(
    user_id: int,
    request_body: ChangeUserRole,
    current_user: User = Depends(get_current_user)):

    db = SessionLocal()
    new_role = request_body.new_role

    # Check if the current user is an admin
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can change user roles",
        )
    
    # Check if the user to be modified exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update the user's role
    user.role = new_role
    db.commit()
    db.refresh(user)
    return user

@app.get("/librarian/clients/{client_id}/books", response_model=List[ShowBooks])
async def get_client_borrowed_books(client_id: int, 
                                    current_user: User = Depends(get_current_user)):

    db = SessionLocal()

    if current_user.role not in ["librarian", "admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden access")

    client = db.query(User).filter(User.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    borrowed_books = db.query(Book).filter(Book.borrower_id == client_id).all()
    return borrowed_books

@app.post("/librarian/clients/{client_id}/books/add")
async def add_book_for_client(client_id: int, book_name: str):

    db = SessionLocal()
    
    client = db.query(User).filter(User.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")

    book = db.query(Book).filter(Book.title == book_name).first()
    if not book:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Book not found")

    if book.borrower_id is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, 
                            detail="Book is already borrowed")

    # Assign the book to the client
    book.borrower_id = client.id
    db.commit()
    return {"message": "Book borrowed successfully"}

@app.delete("/librarian/clients/{client_id}/books/{book_name}/delete")
async def delete_book_for_client(client_id: int, book_name: str):

    db = SessionLocal()
    
    client = db.query(User).filter(User.id == client_id).first()
    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client not found")
    
    # Retrieve the book from the database by name
    book = db.query(Book).filter(Book.borrower_id == client.id, Book.title == book_name).first()
    if not book:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="Book not found for this client")

    # Remove the book from the client's borrowed books
    book.borrower_id = None
    db.commit()
    return {"message": "Book returned successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
