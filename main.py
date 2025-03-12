from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
import secrets
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "your-refresh-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Email configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@example.com")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Authentication API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add custom exception handlers
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenData(BaseModel):
    username: Optional[str] = None

class EmailVerificationRequest(BaseModel):
    token: str

class ResendVerificationRequest(BaseModel):
    email: EmailStr

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def send_verification_email(email: str, token: str):
    """Send verification email to user"""
    if not SMTP_USER or not SMTP_PASSWORD:
        # In development, just print the token
        print(f"Verification token for {email}: {token}")
        print(f"Verification URL: {FRONTEND_URL}/verify-email?token={token}")
        return
    
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = "Verify Your Email Address"
        message["From"] = SMTP_FROM_EMAIL
        message["To"] = email
        
        verification_url = f"{FRONTEND_URL}/verify-email?token={token}"
        
        text = f"""Please verify your email address by clicking the link below:
{verification_url}

Or copy this token: {token}
"""
        
        html = f"""<html>
<body>
<h2>Verify Your Email Address</h2>
<p>Please verify your email address by clicking the link below:</p>
<p><a href="{verification_url}">Verify Email</a></p>
<p>Or copy this token: <code>{token}</code></p>
</body>
</html>"""
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)
        
        await aiosmtplib.send(
            message,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
            start_tls=True,
        )
    except Exception as e:
        print(f"Error sending email: {e}")
        # In development, just print the token
        print(f"Verification token for {email}: {token}")

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", response_model=UserResponse)
@limiter.limit("5/minute")
async def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    log_info(f"Registration attempt for email: {user.email}")
    db_user_email = get_user_by_email(db, email=user.email)
    if db_user_email:
        log_warning(f"Registration failed: Email already registered - {user.email}")
        raise HTTPException(status_code=400, detail="Email already registered")
    
    db_user_username = get_user_by_username(db, username=user.username)
    if db_user_username:
        log_warning(f"Registration failed: Username already taken - {user.username}")
        raise HTTPException(status_code=400, detail="Username already taken")
    
    hashed_password = get_password_hash(user.password)
    verification_token = secrets.token_urlsafe(32)
    
    db_user = User(
        email=user.email, 
        username=user.username, 
        hashed_password=hashed_password,
        is_verified=False,
        verification_token=verification_token
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Send verification email
    await send_verification_email(user.email, verification_token)
    log_info(f"User registered successfully: {user.username}")
    
    return db_user

@app.post("/token", response_model=Token)
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please check your email for verification link."
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    
    # Store refresh token in database
    user.refresh_token = refresh_token
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh", response_model=Token)
@limiter.limit("10/minute")
async def refresh_token(request: Request, token_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token_data.refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_username(db, username=username)
    if user is None or user.refresh_token != token_data.refresh_token:
        raise credentials_exception
    
    # Create new tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    new_refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    
    # Update refresh token in database
    user.refresh_token = new_refresh_token
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/verify-email")
@limiter.limit("5/minute")
async def verify_email(request: Request, verification: EmailVerificationRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == verification.token).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid verification token")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    user.is_verified = True
    user.verification_token = None
    db.commit()
    
    return {"message": "Email verified successfully"}

@app.post("/resend-verification")
@limiter.limit("3/minute")
async def resend_verification(request: Request, email_data: ResendVerificationRequest, db: Session = Depends(get_db)):
    email = email_data.email
    user = get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    # Generate new verification token
    verification_token = secrets.token_urlsafe(32)
    user.verification_token = verification_token
    db.commit()
    
    await send_verification_email(user.email, verification_token)
    
    return {"message": "Verification email sent"}

@app.post("/password-reset")
@limiter.limit("3/minute")
async def password_reset(request: Request, reset_data: PasswordResetRequest, db: Session = Depends(get_db)):
    """Request password reset"""
    user = get_user_by_email(db, email=reset_data.email)
    if not user:
        # Don't reveal if user exists for security
        return {"message": "If the email exists, a password reset link has been sent"}
    
    reset_token = secrets.token_urlsafe(32)
    user.verification_token = reset_token  # Reuse field for reset token
    db.commit()
    
    log_info(f"Password reset requested for user: {user.username}")
    # In production, send email with reset link
    print(f"Password reset token for {user.email}: {reset_token}")
    
    return {"message": "If the email exists, a password reset link has been sent"}

@app.post("/password-reset/confirm")
@limiter.limit("5/minute")
async def password_reset_confirm(request: Request, reset_data: PasswordResetConfirm, db: Session = Depends(get_db)):
    """Confirm password reset with token"""
    user = db.query(User).filter(User.verification_token == reset_data.token).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid or expired reset token")
    
    # Update password
    user.hashed_password = get_password_hash(reset_data.new_password)
    user.verification_token = None
    db.commit()
    
    log_info(f"Password reset successful for user: {user.username}")
    return {"message": "Password reset successful"}

@app.get("/users/me", response_model=UserResponse)
@limiter.limit("30/minute")
async def read_users_me(request: Request, current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/")
async def root():
    return {"message": "Authentication API is running"}

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "authentication-api"
    }

