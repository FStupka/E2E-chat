from sqlalchemy import create_engine
from models import Base
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()  # by default, it looks for a file named ".env" in the current directory

# Access environment variables
db_user = os.getenv("POSTGRES_USER")
db_pass = os.getenv("POSTGRES_PASSWORD")
db_dat = os.getenv("POSTGRES_DB")
DATABASE_URL = f"postgresql+psycopg2://{db_user}:{db_pass}@localhost:5432/{db_dat}"

engine = create_engine(DATABASE_URL, echo=True)

def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")

if __name__ == "__main__":
    init_db()
