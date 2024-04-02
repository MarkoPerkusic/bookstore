from typing import Optional
from pydantic import BaseModel, EmailStr, validator, SecretStr
from sqlalchemy import Table, Column, Integer, ForeignKey, String
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


##################### SQLAlchemy models for input validation #####################

Base = declarative_base()

# SQLAlchemy User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

    # Define relationship with Book model
    books = relationship("Book", back_populates="users")

# SQLAlchemy Book model
class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String)
    author = Column(String)
    borrower_id = Column(Integer, ForeignKey("users.id"))

    # Define relationship with User model
    users = relationship("User", back_populates="books")


##################### Pydantic models for input validation #####################

class BaseRegistration(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: SecretStr

    @validator("password")
    def validate_password_length(cls, pswrd):
        if len(pswrd.get_secret_value()) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return pswrd


class CustomerRegistration(BaseRegistration):
    role: Optional[str] = "customer"


class AdminRegistration(BaseRegistration):
    role: Optional[str] = "admin"


class LibrarianRegistration(BaseRegistration):
    role: Optional[str] = "librarian"

class BookCreate(BaseModel):
    title: str
    author: str

class ShowBooks(BaseModel):
    id: int
    title: str
    author: str

class TokenData(BaseModel):
    sub: Optional[str] = None

class UserModel(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    role: str

class ChangeUserRole(BaseModel):
    new_role: str