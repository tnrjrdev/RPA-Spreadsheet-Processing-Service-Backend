from pydantic import BaseModel

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


