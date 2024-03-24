from typing import Optional
from pydantic import BaseModel, EmailStr, validator, SecretStr
from sqlalchemy import Table, Column, Integer, ForeignKey, String
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


##################### SQLAlchemy models for input validation #####################

Base = declarative_base()

# Association table for the many-to-many relationship
user_books_association = Table(
    "user_books",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("book_id", Integer, ForeignKey("books.id"))
)

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
    books = relationship("Book", secondary=user_books_association, back_populates="users")

# SQLAlchemy Book model
class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String)
    author = Column(String)
    borrower_id = Column(Integer, ForeignKey("users.id"))

    # Define relationship with User model
    users = relationship("User", secondary=user_books_association, back_populates="books")


##################### Pydantic models for input validation #####################

class BaseRegistration(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: SecretStr

    @validator("password")
    def validate_password_length(self, pswrd):
        if len(pswrd.get_secret_value()) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return pswrd


class CustomerRegistration(BaseRegistration):
    role: str = "customer"


class AdminRegistration(BaseRegistration):
    role: str = "admin"


class LibrarianRegistration(BaseRegistration):
    role: str = "librarian"

class BookCreate(BaseModel):
    title: str
    author: str

class TokenData(BaseModel):
    sub: Optional[str] = None