from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db"
    SECRET_KEY: str = "dev"
    GROQ_API_KEY: str = ""
    MAX_LLM_TOKENS: int = 4000  # Default budget for Groq in Stage 8

    class Config:
        env_file = ".env"

settings = Settings()
