from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db"
    SECRET_KEY: str = "dev"
    GROQ_API_KEY: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
