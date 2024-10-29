from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uvicorn import run
from sqlmodel import SQLModel, Field, create_engine
from sqlalchemy.orm import sessionmaker, Session
import hashlib


ENGINE = create_engine("sqlite:///users.db", echo=True)
SESSION = sessionmaker(bind=ENGINE)

def hash_pwd(pwd: str) -> str:
    password_bytes = pwd.encode("utf-8")
    hash_object = hashlib.sha256(password_bytes)
    return hash_object.hexdigest()


async def get_session():
    with SESSION.begin() as session:
        yield session
        
        
        
app = FastAPI()




oauth2_scheme = OAuth2PasswordBearer(tokenUrl="user_token")

class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(SQLModel, table=True):
    username: str = Field(primary_key=True)

    hashed_password: str
    
    
def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )
    
    
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    return user


@app.get("/users/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return {"current_user": current_user}

@app.get("/items/")
async def read_items(current_user: Annotated[User, Depends(get_current_user)]):
    return {"current_user": current_user}


@app.post("/user_token")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[Session, Depends(get_session)],
):
    user = session.get(UserInDB, form_data.username)
    if not user:
        raise HTTPException(status_code=402, detail="Incorrect username or password")

    hashed_password = hash_pwd(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=402, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}




def main():
    SQLModel.metadata.drop_all(ENGINE)
    SQLModel.metadata.create_all(ENGINE)

    with SESSION.begin() as session:
        session.add(
            UserInDB(
                username="user",
                hashed_password=hash_pwd("12345678"),
            )
        )
    run(app)
    

main()




