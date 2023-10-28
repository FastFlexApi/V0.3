from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from databases import Database
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from fastapi.middleware.cors import CORSMiddleware
from registerAccount import FlexUnlimited
import mysql.connector

# Configuración
DATABASE_URL = "mysql+mysqlconnector://botfastflex:Thalia080995%40%23@localhost/mydatabase"





# Inicialización
app = FastAPI()
database = Database(DATABASE_URL)
metadata = MetaData()
engine = create_engine(DATABASE_URL)
flex = FlexUnlimited()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Considera ajustar esto a tu dominio específico por seguridad
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos
class UserResponse(BaseModel):
    status: str
    message: str
    name: str = None
    user_id: int = None
    error_type: str = None

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("username", String, unique=True, index=True),
    Column("password", String),
    Column("name", String)
)

# Eventos de inicio y cierre
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Rutas
@app.post("/register/")
async def register_account(maplanding_url: str):
    result = flex.registerAccount(maplanding_url)
    return {"message": result}

@app.post("/signup/")
async def signup(username: str = Form(...), password: str = Form(...), name: str = Form(...)):
    hashed_password = pwd_context.hash(password)
    query = users_table.insert().values(username=username, password=hashed_password, name=name)
    await database.execute(query)
    return {"message": "User created"}

@app.post("/login/", response_model=UserResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    result = check_user_credentials(form_data.username, form_data.password)
    
    if result["status"] == "error":
        raise HTTPException(status_code=401 if result["error_type"] in ["username", "password"] else 500, detail=result["message"])
    
    return result

# Funciones auxiliares
def create_connection():
    conn = mysql.connector.connect(user="botfastflex", password="Thalia080995@#", database="mydatabase", host="localhost")
    return conn

def check_user_credentials(username, password):
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password, name FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if not result:
            return {"status": "error", "error_type": "username", "message": "Nombre de usuario incorrecto."}

        user_id, stored_password, user_name = result

        if pwd_context.verify(password, stored_password):
            return {"status": "success", "message": "Autenticación exitosa.", "name": user_name, "user_id": user_id}
        else:
            return {"status": "error", "error_type": "password", "message": "Contraseña incorrecta."}

    except mysql.connector.Error:
        return {"status": "error", "error_type": "database_error", "message": "Error en la base de datos."}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



