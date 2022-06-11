from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, DateTime, Integer, create_engine
from datetime import datetime
from flask_login import UserMixin
import os

BASE_DIR=os.path.dirname(os.path.realpath(__file__))
connection_string="sqlite:///"+os.path.join(BASE_DIR,'kolombolo.db')

Base = declarative_base()

engine=create_engine(connection_string, echo=True, connect_args={'check_same_thread': False})

Session=sessionmaker()


class User(UserMixin, Base):
    __tablename__='autor'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    fullname=Column(String(80), nullable=False, unique=True)
    password=Column(String(25), nullable=False, unique=True)
    email=Column(String(80), unique=True, nullable=False)
    date_created=Column(DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return f"<User fullname={self.fullname} email={self.email}>"


