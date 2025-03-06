# Authenticator Backend

A secure FastAPI-based authentication backend with JWT token management, user registration, and protected API endpoints.

## Features

- 🔐 JWT-based authentication
- 🔒 Secure password hashing with bcrypt
- 📝 User registration and login endpoints
- 🛡️ Protected routes with token validation
- 🗄️ SQLite database for user storage
- 🌐 CORS enabled for frontend integration
- 📚 FastAPI with automatic API documentation

## Tech Stack

- **FastAPI** - Modern, fast web framework for building APIs
- **SQLAlchemy** - SQL toolkit and ORM
- **Python-JOSE** - JWT token handling
- **Passlib** - Password hashing utilities
- **Uvicorn** - ASGI server

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Super-Dev-0325/Authenticator-BE.git
cd Authenticator-BE
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
```

3. Activate the virtual environment:
   - **Windows**: `venv\Scripts\activate`
   - **Linux/Mac**: `source venv/bin/activate`

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. (Optional) Create a `.env` file for custom configuration:
```bash
SECRET_KEY=your-secret-key-change-this-in-production
```

## Running the Server

Start the development server:
```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

### API Documentation

Once the server is running, you can access:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## API Endpoints

### Authentication

#### Register User
```http
POST /register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password"
}
```

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "username"
}
```

#### Login
```http
POST /token
Content-Type: multipart/form-data

username: username
password: password
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

#### Get Current User (Protected)
```http
GET /users/me
Authorization: Bearer <token>
```

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "username"
}
```

#### Health Check
```http
GET /
```

**Response:**
```json
{
  "message": "Authentication API is running"
}
```

## Configuration

### Environment Variables

- `SECRET_KEY` - Secret key for JWT token signing (default: "your-secret-key-change-this-in-production")
- `ACCESS_TOKEN_EXPIRE_MINUTES` - Token expiration time in minutes (default: 30)

### Database

The application uses SQLite by default. The database file (`users.db`) will be created automatically in the backend directory.

For production, consider using PostgreSQL or MySQL:
```python
SQLALCHEMY_DATABASE_URL = "postgresql://user:password@localhost/dbname"
```

## Security Considerations

⚠️ **Important for Production:**

1. **Change the SECRET_KEY** - Use a strong, randomly generated secret key
2. **Use environment variables** - Never commit secrets to version control
3. **Use HTTPS** - Always use HTTPS in production
4. **Database security** - Use a production-grade database with proper access controls
5. **Rate limiting** - Implement rate limiting to prevent brute force attacks
6. **Token expiration** - Adjust token expiration times based on your security requirements
7. **CORS configuration** - Restrict CORS origins to your frontend domain only

## Project Structure

```
backend/
├── main.py              # FastAPI application and routes
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
├── README.md           # This file
└── users.db            # SQLite database (created automatically)
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Code Style

This project follows PEP 8 style guidelines. Consider using:
- `black` for code formatting
- `flake8` for linting
- `mypy` for type checking

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Support

For issues and questions, please open an issue on the [GitHub repository](https://github.com/Super-Dev-0325/Authenticator-BE/issues).

## Related Projects

- [Authenticator Frontend](https://github.com/Super-Dev-0325/Authenticator) - React frontend for this authentication system

