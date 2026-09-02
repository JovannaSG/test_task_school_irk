from contextlib import asynccontextmanager
import sqlite3
from random import randint
import re
from hashlib import sha256, pbkdf2_hmac
import os
from binascii import hexlify

import aiosqlite

from starlette.middleware.sessions import SessionMiddleware

from fastapi import Depends, FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.concurrency import run_in_threadpool


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with aiosqlite.connect("users.db") as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()
    yield


app = FastAPI(
    title="«Сервис аутентификации с защитой от ботов» (Регистрация + Вход + CAPTCHA)",
    lifespan=lifespan,
    version="1.0.0"
)
app.add_middleware(SessionMiddleware, secret_key="test_secret_key1")
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


def hash_password(password: str) -> str:
    salt = sha256(os.urandom(60)).hexdigest().encode("ascii")
    pwdhash = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    pwdhash = hexlify(pwdhash)
    return (salt + pwdhash).decode("ascii")


def verify_password(stored_pswd: str, provided_pswd: str) -> bool:
    salt = stored_pswd[:64]
    stored_pwdhash = stored_pswd[64:]
    pwdhash = pbkdf2_hmac(
        "sha256",
        provided_pswd.encode("utf-8"),
        salt.encode("ascii"),
        100000
    )
    pwdhash = hexlify(pwdhash).decode("ascii")
    return pwdhash == stored_pwdhash


def generate_captcha(request: Request) -> tuple[int, int]:
    n1: int = randint(1, 10)
    n2: int = randint(1, 10)
    request.session["captcha_answer"] = n1 + n2
    return n1, n2


async def get_db():
    async with aiosqlite.connect("users.db") as db:
        db.row_factory = aiosqlite.Row
        yield db


@app.get("/")
async def index():
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )


@app.get("/register", response_class=HTMLResponse)
async def get_register(req: Request):
    n1, n2 = generate_captcha(req)
    return templates.TemplateResponse(
        request=req,
        name="register.html",
        context={
            "request": req,
            "number1": n1,
            "number2": n2
        }
    )


@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    captcha: int = Form(...),
    db: aiosqlite.Connection = Depends(get_db)
):
    correct_captcha = request.session.pop('captcha_answer', None)
    n1, n2 = generate_captcha(request)
    username = username.strip()
    email = email.strip()

    # Валидация капчи
    if not correct_captcha or captcha != correct_captcha:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": "Неверный ответ капчи",
                "number1": n1,
                "number2": n2
            }
        )

    # Валидация данных
    if not re.match(r"^[a-zA-Z0-9]{3,20}$", username):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": f"Ошибка: вы ввели '{username}'. Имя пользователя: 3-20 символов латиницы и цифр",
                "number1": n1,
                "number2": n2
            }
        )

    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": "Введите валидный email",
                "number1": n1,
                "number2": n2
            }
        )

    if not re.match(r'^(?=.*[a-zA-Z])(?=.*\d).{6,}$', password):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": "Пароль: минимум 6 символов, буквы и цифры",
                "number1": n1,
                "number2": n2
            }
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": "Пароли не совпадают",
                "number1": n1,
                "number2": n2
            }
        )

    # Сохранение в БД
    hashed_password = await run_in_threadpool(hash_password, password)
    try:
        await db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        await db.commit()
    except sqlite3.IntegrityError as e:
        error_msg = "Пользователь с таким именем или email уже существует"
        if "username" in str(e).lower():
            error_msg = "Пользователь с таким именем уже существует"
        elif "email" in str(e).lower():
            error_msg = "Пользователь с таким email уже зарегистрирован"
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "request": request,
                "error": error_msg,
                "number1": n1,
                "number2": n2
            }
        )
    request.session["flash_success"] = "Регистрация успешна. Войдите в систему."
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )


@app.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    if "user_id" in request.session:
        return RedirectResponse(
            url="/profile",
            status_code=status.HTTP_302_FOUND
        )

    success_msg = request.session.pop("flash_success", None)
    n1, n2 = generate_captcha(request)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "number1": n1,
            "number2": n2,
            "success": success_msg
        }
    )


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    login_input: str = Form(...),
    password: str = Form(...),
    captcha: int = Form(...),
    db: aiosqlite.Connection = Depends(get_db)
):
    correct_captcha = request.session.pop("captcha_answer", None)
    n1, n2 = generate_captcha(request)

    if not correct_captcha or captcha != correct_captcha:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "error": "Неверный логин или пароль (или капча)",
                "number1": n1,
                "number2": n2
            }
        )

    # Поиск пользователя в БД
    user = None
    async with db.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (login_input, login_input)
    ) as cursor:
        user = await cursor.fetchone()

    print(f"Результат поиска (user): {user}")
    if user is None:
        return templates.TemplateResponse(
            request=request,
            name="login.html", 
            context={
                "request": request,
                "error": "Неверный логин или пароль",
                "number1": n1,
                "number2": n2
            }
        )

    is_valid = await run_in_threadpool(
        verify_password,
        user['password_hash'],
        password
    )
    if user and is_valid:
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        request.session["created_at"] = user["created_at"]
        return RedirectResponse(
            url="/profile",
            status_code=status.HTTP_302_FOUND
        )
    else:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "error": "Неверный логин или пароль",
                "number1": n1,
                "number2": n2
            }
        )


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    if "user_id" not in request.session:
        return RedirectResponse(
            url="/login",
            status_code=status.HTTP_302_FOUND
        )

    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "request": request,
            "username": request.session["username"],
            "email": request.session["email"],
            "created_at": request.session["created_at"]
        }
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(
        url="/login",
        status_code=status.HTTP_302_FOUND
    )
