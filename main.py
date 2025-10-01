from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer
from database import SessionLocal, engine
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import models, schemas, auth

import pandas as pd
import io

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],   
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "rpa_secret_key"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@app.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Usuário já existe.")
    hashed = auth.hash_password(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login", response_model=schemas.Token)
def login(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if not db_user or not auth.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    token = auth.create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username
    }

@app.post("/clients/", response_model=schemas.ClientResponse)
def create_client(client: schemas.ClientCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_client = db.query(models.Client).filter(models.Client.email == client.email).first()
    if db_client:
        raise HTTPException(status_code=400, detail="Cliente já existe")
    new_client = models.Client(name=client.name, email=client.email)
    db.add(new_client)
    db.commit()
    db.refresh(new_client)
    return new_client

@app.get("/clients/", response_model=List[schemas.ClientResponse])
def read_clients(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    clients = db.query(models.Client).offset(skip).limit(limit).all()
    return clients

@app.get("/clients/{client_id}", response_model=schemas.ClientResponse)
def read_client(client_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    return client

@app.put("/clients/{client_id}", response_model=schemas.ClientResponse)
def update_client(client_id: int, client_update: schemas.ClientCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    client.name = client_update.name
    client.email = client_update.email
    db.commit()
    db.refresh(client)
    return client

@app.delete("/clients/{client_id}", status_code=204)
def delete_client(client_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Cliente não encontrado")
    db.delete(client)
    db.commit()
    return

# ----------------
# ROTAS PLANILHA:
# ----------------

dados_planilha_temp = {}

@app.post("/upload/", summary="Upload de planilha CSV/XLSX")
async def upload_planilha(
    file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user)
):
    ext = file.filename.split('.')[-1]
    content = await file.read()
    try:
        if ext == "csv":
            df = pd.read_csv(io.BytesIO(content))
        elif ext in ("xlsx", "xls"):
            df = pd.read_excel(io.BytesIO(content))
        else:
            raise HTTPException(status_code=400, detail="Formato de arquivo não suportado")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Falha ao ler arquivo: {e}")

    dados_planilha_temp[current_user.id] = df.to_dict(orient='records')
    return {"msg": "Arquivo recebido", "total": len(dados_planilha_temp[current_user.id])}

@app.get("/dados/", summary="Listar dados enviados pela planilha")
def listar_dados(current_user: models.User = Depends(get_current_user)):
    return dados_planilha_temp.get(current_user.id, [])
