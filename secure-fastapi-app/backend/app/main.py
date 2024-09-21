from fastapi import FastAPI, Depends, HTTPException, Form, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import html
import bleach
import time

app = FastAPI()

# Configuração das origens permitidas
origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    # Adicione outras origens permitidas aqui, como o domínio do frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Permitir essas origens
    allow_credentials=True,  # Permitir o envio de cookies e credenciais
    allow_methods=["*"],  # Permitir todos os métodos HTTP
    allow_headers=["*"],  # Permitir todos os cabeçalhos
)


@app.middleware("http")
async def verify_host(request: Request, call_next):
    """Request to prevent Host Header Injection."""
    start_time = time.time()
    if 'user-agent' in request.headers:
        if 'kube-probe' not in request.headers['user-agent']:
            if request.headers['Host'] not in ["localhost:8000"] \
                    or 'X-Forwarded-Host' in request.headers:
                return JSONResponse(
                    content={'detail': 'UNAUTHORIZED'},
                    status_code=status.HTTP_401_UNAUTHORIZED
                )

    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Secret key e algoritmo para o JWT
SECRET_KEY = "65a8e27d8879283831b664bd8b7f0ad4"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simulação de banco de dados em memória
fake_users_db = {
    "user": {
        "username": "user",
        "hashed_password": "$2b$12$iwmwb0D96/0YYvkExnif1ePnmMNJL9WQHOuerlsFqRAuzM6o8xq3u"  # 'password' hashed
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def sanitize_input(input_value: str) -> str:
    """
    Sanitiza as entradas para prevenir XSS e outras injeções.
    Utiliza o bleach para remover tags HTML perigosas e html.escape para escapar caracteres especiais.
    """
    return bleach.clean(html.escape(input_value))


def authenticate_user(fake_db, username: str, password: str):
    sanitized_username = sanitize_input(username)
    user = fake_db.get(sanitized_username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Sanitizando as entradas
    sanitized_username = sanitize_input(form_data.username)
    sanitized_password = sanitize_input(form_data.password)

    user = authenticate_user(fake_users_db, sanitized_username, sanitized_password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user


@app.get("/secure-data")
async def read_secure_data(current_user: dict = Depends(get_current_user)):
    sanitized_username = sanitize_input(current_user['username'])
    return {"message": f"Hello, {sanitized_username}"}
