import hmac
import base64
import hashlib
import binascii
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response # данные и методы обработки запросов


# экземпляр приложения fastapi
app = FastAPI()

"""Можно сгенерить с помощью команды: openssl rand -hex 32"""
SECRET_KEY = "6eaf6f2aa5977ab3efbdb2ad3d8957cbbf25d52a9cb8686f1f8813be3b7b83f7"
# именованная константа со значением
PASSWORD_SALT = "731d8cc0c683fddf642d83064ee607b8e90e129c3279dcae14d3dfa8e3df5b4b"
"""
------------------------------------------------------------------------------
Для обеспечения безопасности именованные константы с ключами нужно хранить 
в переменной окружения $PATH
------------------------------------------------------------------------------
"""

def sign_data(data: str) -> str:
    """Получаем hash из данных c использованием 
    SECRET_KEY"""
    return hmac.new(
        # Ключ в байтах
        SECRET_KEY.encode(),
        # data в байтах, (str) в bite 
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()
"""
------------------------------------------------------------------------------
для проверки вызываем в интерактивном режиме from server import sign_data
------------------------------------------------------------------------------
"""

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    """
    Получаем корректный email из подписанной строки если функция правильная,
    либо None если неправильная
    """
    if "." not in username_signed:
        return None 
    username_base64, sign = username_signed.split(".")
    try:
        username = base64.b64decode(username_base64.encode()).decode()
    except binascii.Error:
        return None
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        # Сравниваем подписанные данные с исходными
        return username
    else:
        return None

"""
------------------------------------------------------------------------------
base64 для username нужен по факту просто чтобы убрать точки в username
------------------------------------------------------------------------------
"""

def verify_password(username: str, password: str) -> bool:
    """Функция проверки пароля"""
    password_hash = hashlib.sha256((password + PASSWORD_SALT)
            .encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

"""
------------------------------------------------------------------------------
Ниже в  нашей "БД" мы храним хэш паролей, сгенерированные в интерактивном
режиме с помощью:
1. import hashlib
2. from server import PASSWORD_SALT
3. hashlib.sha256(("some_password_1" + PASSWORD_SALT).encode()).hexdigest()
тут мы подсаливаем(добавляем PASSWORD_SALT) наш пароль, и возврашаем 
шестнадцатеричную строку, т.е. хэш функцию
------------------------------------------------------------------------------
"""


users = {
    "victor@mail.com": {
        "name": "Виктор",
        "password": "bc36955062b884cd8e06324b68ecaf6a577f00a734fe6aa0420c3d8ddab1e047",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Пётр",
        "password": "f4efdbc1d5619c9c2c0f873f17e8eecc7fb044d2a5fe8f355efc71c7e2def2f3",
        "balance": 555_555
    }
}


# decorator @, когда придет запрос get на корневую страницу(/)
# функция index_page запустится
@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    """функция, которая обрабатыавет http запрос"""
    # если cookie не установлена, то в значении username будет None
    
    with open('templates/login.html','r') as f: # открываем файл с html
        login_page = f.read()
    
    # если cookie пустая
    if not username:
        return Response(login_page, media_type="text/html") 
    
    valid_username = get_username_from_signed_string(username)
        
    # попытка взлома с невалидной подписью
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    
    # проверка пользователя и отлов ошибки отсутствия KeyValue
    # дабы избежать падения сервера с ошибкой 500
    # если подменить значение username через ch dev tools
    # например document.cookie = 'username="petr@usr.com"'
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Привет, {users[valid_username]['name']}!<br /> \
                    Баланс: {users[valid_username]['balance']}",
                    media_type="text/html")
"""
______________________________________________________________________________
это не страхует от подмены cookie,  т.е. если известен юзернэйм, без ввода
пароля сервак пустит этого пользователя, запретить менять куки мы не можем,
т.к. они хранятся в браузере, поэтому мы посписываем с помощью функции
sing_data используя хэш функцию, известную только нам
______________________________________________________________________________

"""
@app.post("/login")
def process_login_page(data: dict = Body(...)):
    """Функция достает атрибуты из POST(Form Data) из фронтэнда, чтобы принять
    из на бэкэнде и проверяет есть ли пара пароль польззователь в БД""" 
    # чтобы fastapi достал из http POST запроса в поле Form Data
    # как атрибуты фукнкции process_login_page
    username = data["username"]
    password = data["password"]

    user = users.get(username)
    # user = users[username] не используем, т.к. вернет KeyValueError,
    # а user.get(username) вернет просто пустое значение
    if not user or not verify_password(username, password):
        # проверка имени пользователя или пароля
        return Response(
            json.dumps({
                "succes": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}! <br /> Баланс: {user['balance']}"  
        }),
        media_type="application/json")
    
    # конвертируем username в набор ASCII символов и добавляем подписанное
    # имя пользователя
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username) 
    # метод fastAPI, который позволяет установить cookie, Set-Coockie http
    response.set_cookie(key="username", value=username_signed)
    return response

""" 
Запускаем сервер с помощью:
uvicorn server:app --reload
------------------------------------------------------------------------------
uvicorn берет питоновский модуль с названием server, в нем ищет глобальную
переменную app(экземпляр FastAPI) и --reload, чтобы uvicorn перезагрузил
приложение для отображения изменений
______________________________________________________________________________
"""

