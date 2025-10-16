import os
import boto3
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from mangum import Mangum


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_key = os.environ.get("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

stage = os.environ.get('API_GATEWAY_STAGE')
root_path = f"/{stage}" if stage else ""

# --- DynamoDB Connection ---
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get("TABLE_NAME")
table = dynamodb.Table(table_name)

# --- Pydantic Models ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    id: EmailStr
    email: EmailStr

# --- Helper Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_key, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_key, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    response = table.get_item(Key={'email': email})
    user = response.get('Item')
    
    if user is None:
        raise credentials_exception
    
    user['id'] = user['email']
    return user

# --- FastAPI App & Endpoints ---
app = FastAPI(title="Vectorial AI Auth Service - DynamoDB", root_path=root_path)

@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register_user(user: UserCreate):
    response = table.get_item(Key={'email': user.email})
    if 'Item' in response:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    table.put_item(Item={"email": user.email, "hashed_password": hashed_password})
    
    return {"id": user.email, "email": user.email}

@app.post("/auth/login", response_model=Token, tags=["Auth"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    response = table.get_item(Key={'email': form_data.username})
    user = response.get('Item')
    
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse, tags=["Users"])
def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user_by_id(user_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["email"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this user")
    
    table.delete_item(Key={'email': user_id})
    return None

handler = Mangum(app)