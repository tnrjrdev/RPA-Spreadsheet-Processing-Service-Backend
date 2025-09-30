from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
  username: str
  password: str

class UserResponse(BaseModel):
  id: int
  username: str

  model_config = {
    "from_attributes": True
}


class Token(BaseModel):
  access_token: str
  token_type: str


class ClientBase(BaseModel):
    name: str
    email: EmailStr

class ClientCreate(ClientBase):
    pass

class ClientResponse(ClientBase):
    id: int

    class Config:
      from_attributes = True

