from unittest.mock import MagicMock
import pytest
from app.models import User
from app.main import *
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

client = TestClient(app)


@pytest.mark.parametrize(
    "username, password, expected_status_code",
    [
        ("test@example.com", "password", 200),
        ("invalid@example.com", "password", 401),
        ("test@example.com", "invalid_password", 401),
        ("invalid@example.com", "invalid_password", 401),
    ]
)
def test_login_user(username, password, expected_status_code, monkeypatch):
    """
    Test the login functionality with different username and password combinations.

	Parameters:
	    username (str): The username for logging in.
	    password (str): The password for logging in.
	    expected_status_code (int): The expected status code of the response.
	    monkeypatch (fixture): Pytest fixture for mocking.

	Returns:
	    None
	"""

    class MockUser:
        """
        Represents a mock user object for simulating user data during testing.
        This class is used to create mock user objects with flexible attributes for testing purposes.
        It can accept various combinations of parameters such as email, role, and first name.

        Parameters:
            email (str): The email of the user.
            role (str): The role of the user.
            first_name (str): The first name of the user.
        """

        def __init__(self, email, role, first_name):
            self.email = email
            self.role = role
            self.first_name = first_name

    def mock_authenticate_user(email, role, db):
        """
        Generates a mock user object for testing purposes.

        Parameters:
            email (str): The email of the user.
            role (str): The role of the user.
            db (Database): The database object to interact with.

        Returns:
            MockUser: A mock user object with specified email, role, and first name.
        """
        return MockUser(email=email, role="test_role", first_name="test_name")

    def mock_create_access_token(data, expires_delta):
        """
        A function that mocks the creation of an access token.

        Parameters:
            data (any): The data used to create the access token.
            expires_delta (int): The expiration time delta for the access token.

        Returns:
            str: A test access token.
        """
        return 'test_access_token'

    if expected_status_code == 200:
        monkeypatch.setattr('app.main.authenticate_user', mock_authenticate_user)
        monkeypatch.setattr('app.main.create_access_token', mock_create_access_token)

    response = client.post('/login', data={'username': username, 'password': password})

    assert response.status_code == expected_status_code
    if expected_status_code == 200:
        assert response.json() == {
            "access_token": "test_access_token",
            "token_type": "bearer",
            "role": "test_role",
            "name": "test_name"
        }


def test_delete_book_for_client_when_client_not_found(monkeypatch):
    """
    Test case to verify the behavior when attempting to delete a book for a client that doesn't exist.

    This test mocks the database session and the query to return None, simulating the absence of the client.
    It then sends a DELETE request to the endpoint and asserts that the response status code is 404 (Not Found)
    with the appropriate error message.
    """

    # Mock SessionLocal and its query method
    mock_session_local = MagicMock()
    monkeypatch.setattr("app.main.SessionLocal", mock_session_local)
    
    # Mock db.query(User).filter(User.id == client_id).first() to return None
    mock_query_user = MagicMock(return_value=None)
    mock_session_local.return_value.query.return_value.filter.return_value.first = mock_query_user
    
    response = client.delete('/librarian/clients/1/books/Test Book/delete')
    
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Client not found"}

def test_delete_book_for_client_when_book_not_found(monkeypatch):
    """
    Test case to verify the behavior when attempting to delete a book that doesn't exist.

    This test mocks the database session and the queries to return a valid user and None for the book,
    simulating the scenario where the book is not found for the given client.
    It then sends a DELETE request to the endpoint and asserts that the response status code is 404 (Not Found)
    with the appropriate error message.
    """
    
    # Mock SessionLocal and its query method
    mock_session_local = MagicMock()
    monkeypatch.setattr("app.main.SessionLocal", mock_session_local)
    
    # Mock db.query(User).filter(User.id == client_id).first() to return a valid user
    mock_user = User(id=1)
    mock_query_user = MagicMock(return_value=mock_user)
    mock_session_local.return_value.query.return_value.filter.return_value.first = mock_query_user
    
    # Mock db.query(Book).filter(Book.borrower_id == client.id, Book.title == book_name).first() to return None
    mock_query_book = MagicMock(return_value=None)
    mock_session_local.return_value.query.return_value.filter.return_value.first = mock_query_book
    
    response = client.delete('/librarian/clients/1/books/Test Book/delete')
    
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Client not found"}

def test_delete_book_for_client_successfully(monkeypatch):
    """
    Test case to verify the successful deletion of a book for a client.

    This test mocks the database session and the queries to return a valid user and a valid book,
    simulating the scenario where the book exists for the given client.
    It then sends a DELETE request to the endpoint and asserts that the response status code is 200 (OK)
    with the appropriate success message.
    """

    # Mock SessionLocal and its query method
    mock_session_local = MagicMock()
    monkeypatch.setattr("app.main.SessionLocal", mock_session_local)
    
    # Mock db.query(User).filter(User.id == client_id).first() to return a valid user
    mock_user = User(id=1)
    mock_query_user = MagicMock(return_value=mock_user)
    mock_session_local.return_value.query.return_value.filter.return_value.first = mock_query_user
    
    # Mock db.query(Book).filter(Book.borrower_id == client.id, Book.title == book_name).first() to return a valid book
    mock_book = Book(id=1, borrower_id=1, title="Test Book")
    mock_query_book = MagicMock(return_value=mock_book)
    mock_session_local.return_value.query.return_value.filter.return_value.first = mock_query_book
    
    response = client.delete('/librarian/clients/1/books/Test Book/delete')
    
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Book returned successfully"}
