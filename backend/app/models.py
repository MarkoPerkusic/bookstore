from typing import Optional
from pydantic import BaseModel, EmailStr, validator, SecretStr
from sqlalchemy import Table, Column, Integer, ForeignKey, String
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


##################### SQLAlchemy models for input validation #####################

Base = declarative_base()

# SQLAlchemy User model
class User(Base):
    """
    Represents a user in the system.

    Attributes:
        id (int): The unique identifier of the user.
        first_name (str): The first name of the user.
        last_name (str): The last name of the user.
        email (str): The email address of the user.
        password (str): The hashed password of the user.
        role (str): The role of the user in the system.
    """

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
    """
    Represents a book in the system.

    Attributes:
        id (int): The unique identifier of the book.
        title (str): The title of the book.
        author (str): The author of the book.
        borrower_id (int): The ID of the user who borrowed the book.
    """

    __tablename__ = "books"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String)
    author = Column(String)
    borrower_id = Column(Integer, ForeignKey("users.id"))

    # Define relationship with User model
    users = relationship("User", back_populates="books")


##################### Pydantic models for input validation #####################

class BaseRegistration(BaseModel):
    """
    Base model for user registration.

    Attributes:
        first_name (str): The first name of the user.
        last_name (str): The last name of the user.
        email (EmailStr): The email address of the user.
        password (SecretStr): The password of the user.
    """

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
    """
    Model for customer registration, inheriting from BaseRegistration.

    Attributes:
        role (str, optional): The role of the user. Defaults to "customer".
    """

    role: Optional[str] = "customer"


class AdminRegistration(BaseRegistration):
    """
    Model for admin registration, inheriting from BaseRegistration.

    Attributes:
        role (str, optional): The role of the user. Defaults to "admin".
    """

    role: Optional[str] = "admin"


class LibrarianRegistration(BaseRegistration):
    """
    Model for librarian registration, inheriting from BaseRegistration.

    Attributes:
        role (str, optional): The role of the user. Defaults to "librarian".
    """

    role: Optional[str] = "librarian"

class BookCreate(BaseModel):
    """
    Model for creating a book.

    Attributes:
        title (str): The title of the book.
        author (str): The author of the book.
    """

    title: str
    author: str

class ShowBooks(BaseModel):
    """
    Model for displaying book details.

    Attributes:
        id (int): The unique identifier of the book.
        title (str): The title of the book.
        author (str): The author of the book.
    """

    id: int
    title: str
    author: str

class TokenData(BaseModel):
    """
    Model for token data.

    Attributes:
        sub (str, optional): The subject of the token.
    """

    sub: Optional[str] = None

class UserModel(BaseModel):
    """
    Model for user data.

    Attributes:
        id (int): The unique identifier of the user.
        first_name (str): The first name of the user.
        last_name (str): The last name of the user.
        email (str): The email address of the user.
        role (str): The role of the user.
    """

    id: int
    first_name: str
    last_name: str
    email: str
    role: str

class ChangeUserRole(BaseModel):
    """
    Model for changing user role.

    Attributes:
        new_role (str): The new role to be assigned.
    """
    
    new_role: str