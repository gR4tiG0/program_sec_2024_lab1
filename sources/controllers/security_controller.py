from argon2 import PasswordHasher
from json import loads, dumps
from string import ascii_letters, punctuation
from errors import *
from controllers.log_controller import *

ARITHM_SYMBOLS = "+-*/^"
EMPTY_PASS = "$argon2id$v=19$m=65536,t=3,p=4$NodMK2Xf9JVoqiDtGECPAA$5RPg74/I5hoSgeeqpgytsIlBWMI0jNZDh80ajBGD8dw"
DB_FILEPATH = 'json/database.json'

def initDB() -> None: 
    try:
        log(INFO_LOG, "Loading database file")
        with open(DB_FILEPATH, 'r') as f:
            data = loads(f.read())
    except:
        log(INFO_LOG, "Database file not found, creating new one")
        data = {
            "ADMIN": {
                "password": EMPTY_PASS,
                "role": "admin",
                "restricted": False,
                "force_change_password": True,
                "banned": False,
                "inc_att": 0
            }
        }
        with open(DB_FILEPATH, 'w') as f:
            f.write(dumps(data))

def checkPassword(username:str, password:str) -> bool:
    with open(DB_FILEPATH, 'r') as f:
        database = loads(f.read())
    
    ph = PasswordHasher()
    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, password)
    except:
        return False
    return True

def checkLogin(username:str, password:str) -> dict:

    ph = PasswordHasher()

    with open(DB_FILEPATH, 'r') as f:
        database = loads(f.read())

    if username not in database:
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {INC_USER_ERR}")
        return {"Error": INC_LOGIN_ERR}
    
    if database[username]["banned"]:
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {USER_BAN_ERR}")
        return {"Error": USER_BAN_ERR}
    
    if database[username]["force_change_password"]:
        log(INFO_LOG, f"Attemp to login as '{username}' failed. Reason: {CHANGE_PASS_ERR}")
        user = {"username": username, "role": database[username]["role"]}
        return {"Info": CHANGE_PASS_ERR, "user": user}

    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, password)
    except:
        error = INC_LOGIN_ERR
        database[username]["inc_att"] += 1
        log(ERR_LOG, f"Attemp to login as '{username}' failed. Reason: {INC_PASS_ERR}")

        if database[username]["inc_att"] >= 3:
            database[username]["banned"] = True
            database[username]["force_change_password"] = True
            error = ATT_BAN_ERR
            log(ERR_LOG, f"User '{username}' banned, reason: {ATT_BAN_ERR}")

        with open(DB_FILEPATH, 'w') as f:
            f.write(dumps(database))

        return {"Error": error}

    log(INFO_LOG, f"User '{username}' logged in")
    database[username]["inc_att"] = 0
    with open(DB_FILEPATH, 'w') as f:
        f.write(dumps(database))
    return {"username": username, "role": database[username]["role"]}

def checkPasswordRestrictions(password:str) -> bool:
    if (
        any(char in ascii_letters for char in password) and
        any(char in punctuation for char in password) and
        any(char in ARITHM_SYMBOLS for char in password)
    ):
        return True
    return False

def changePassword(old_password:str, new_password:str, user:dict) -> dict:
    with open(DB_FILEPATH, 'r') as f:
        database = loads(f.read())

    if database[user["username"]]["restricted"]:
        if not checkPasswordRestrictions(new_password):
            log(ERR_LOG, f"Attempt to change password for restricted user '{user['username']}' failed. Reason: {PASS_RESRT_ERR}")
            return {"Error": PASS_RESRT_ERR}
    
    ph = PasswordHasher()
    
    

    username = user["username"]
    stored_password = database[username]["password"]
    try:
        ph.verify(stored_password, old_password)
    except:    
        log(ERR_LOG, f"Attempt to change password for user '{username}' failed. Reason: {INC_PASS_ERR}")
        return {"Error": INC_PASS_ERR}
    
    database[username]["password"] = ph.hash(new_password)
    database[username]["force_change_password"] = False
    with open(DB_FILEPATH, 'w') as f:
        f.write(dumps(database))
    
    log(INFO_LOG, f"Password for user '{username}' changed")
    return user