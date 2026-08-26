from sqlalchemy.orm import declarative_base
Base = declarative_base()
class Case(Base):
    __tablename__ = 'cases'
    id = None
