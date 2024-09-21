from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from starlette.responses import HTMLResponse
import uvicorn

# Configurações
SECRET_KEY = "65a8e27d8879283831b664bd8b7f0ad4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Modelo de Dados
class User(BaseModel):
    username: str
    password: str


# Dados de Usuário Fictício
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "password"
    }
}


# Função para criar um token JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Endpoint de Login
@app.post("/token")
async def login(user: User):
    user_in_db = fake_users_db.get(user.username)
    if not user_in_db or user.password != user_in_db['password']:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# Função para obter o usuário atual
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


# Endpoint vulnerável a XSS
@app.get("/profile", response_class=HTMLResponse)
async def read_profile(username: str = Depends(get_current_user)):
    # Retorna o nome de usuário diretamente no HTML sem sanitização
    return f"""
    <html>
        <body>
            <h1>Profile</h1>
            <p>Username: {username}</p>
        </body>
    </html>
    """


# Iniciar o servidor programaticamente
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=7500, reload=True)
