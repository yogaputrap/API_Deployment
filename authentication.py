from fastapi import APIRouter, HTTPException, Depends, status, Request, Form
from fastapi.encoders import jsonable_encoder
import json
from pydantic import BaseModel
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
    
class User:
    def __init__(self, customer_id, username, password_hash):
        self.customer_id = customer_id
        self.username = username
        self.password_hash = password_hash

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

json_filename = "users.json"

with open(json_filename,"r") as read_file:
	data = json.load(read_file)

def write_data(data):
    with open(json_filename, "w") as write_file:
        json.dump(data, write_file, indent=4)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
JWT_SECRET = 'myjwtsecret'
ALGORITHM = 'HS256'
router = APIRouter(tags=["Authentication"])

def get_user_by_username(username):
    for user in data['user']:
        if user['username'] == username:
            return user
    return None

def authenticate_user(username: str, password: str):
    user_data = get_user_by_username(username)
    if not user_data:
        return None

    user = User(customer_id=user_data['customer_id'], username=user_data['username'],
                password_hash=user_data['password_hash'])

    if not user.verify_password(password):
        return None

    return user

@router.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        print(f"Invalid username or password for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    token = jwt.encode({'customer_id': user.customer_id, 'username': user.username},
                       JWT_SECRET, algorithm=ALGORITHM)

    return {'access_token': token, 'token_type': 'bearer'}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = get_user_by_username(payload.get('username'))
        return User(customer_id=user['customer_id'], username=user['username'],
                    password_hash=user['password_hash'])
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid username or password'
        )

@router.post('/users')
async def create_user(username: str, password: str):
    if not data['user']:
        last_user_id = 0
    else:
        last_user_id = max(user['customer_id'] for user in data['user'])

    user_id = last_user_id + 1
    user = jsonable_encoder(User(customer_id=user_id, username=username,
                                 password_hash=bcrypt.hash(password)))
    data['user'].append(user)
    write_data(data)
    return {'message': 'User created successfully', 'customer_id': user_id}

@router.get('/users/me')
async def get_user(user: User = Depends(get_current_user)):
    return {'customer_id': user.customer_id, 'username': user.username, 'role': 'admin'}
