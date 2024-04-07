# bookstore
This is a bookstore application built with React for the frontend and FastAPI for the backend.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)

## Introduction

Simple backend solution for a bookstore webpage using FastAPI and Python. Includes user and book management with role-based access control. Ideal for creating a bookstore application with admin, librarian, and customer roles. This application allows users to register, login, and browse a collection of books. Users can also add books to their cart and place orders. Registration of a new admin or librarian, and also update of roles are supposed to be done via API without the UI implementation.
The frontend part is implemented in ReactJS and is located in separete repo - https://github.com/MarkoPerkusic/bookstore_frontend

## Installation

1. Clone the repository:

    git clone https://github.com/MarkoPerkusic/bookstore

2. Navigate into the project directory:

    cd bookstore

3. Install dependencies:

    pip install -r requirements.txt

Make sure to have PostgreSQL installed and running. You'll need to manually create books in the database, as the application currently does not have functionality to create books automatically.

## Usage

To start the backend server, run:

    uvicorn backend.app.main:app --reload

To start the frontend server, run:

    npm start

Features

- User registration and login
- Browse books
- Add books to cart
- Place orders

API Documentation

Since the backend code is implemented in FastAPI, the API documentation can be found at:

    http://127.0.0.1:8000/docs

This documentation provides detailed information about the available endpoints, request/response formats, and parameters.

Running Tests

Unit tests can be executed by calling pytest from the root of the app:

    pytest