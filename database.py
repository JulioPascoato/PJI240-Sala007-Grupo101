from sqlalchemy.orm import declarative_base, sessionmaker, relationship, backref
from sqlalchemy import Column, ForeignKey, String, DateTime, Integer, create_engine, Table
from datetime import datetime
from flask_login import UserMixin
import os


BASE_DIR=os.path.dirname(os.path.realpath(__file__))
connection_string="sqlite:///"+os.path.join(BASE_DIR,'kolombolo.db')

Base = declarative_base()

engine=create_engine(connection_string, echo=True, connect_args={'check_same_thread': False})

Session=sessionmaker()


acervo_protagonista = Table(
        'acervo_protagonista',
        Base.metadata,
        Column('acervo_id', Integer, ForeignKey('acervo.id')),
        Column('protagonista_id', Integer, ForeignKey('protagonista.id')),
)


class User(UserMixin, Base):
    __tablename__='autor'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    fullname=Column(String(80), nullable=False, unique=True)
    password=Column(String(25), nullable=False, unique=True)
    email=Column(String(80), unique=True, nullable=False)
    date_created=Column(DateTime(), default=datetime.utcnow)

    # User add many acervo_posts
    acervo_posts = relationship("Acervo", backref='autor')


    def __repr__(self):
        return f"<User fullname={self.fullname} email={self.email}>"


class Midia(Base):
    __tablename__='tipo'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    name=Column(String(80), nullable=False, unique=True)
    

    def __repr__(self):
        return f"<Midia name={self.name}>"


class Protagonista(Base):
    __tablename__='protagonista'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    name=Column(String(80), nullable=False, unique=True)


    def __repr__(self):
        return f"<Protagonista name={self.name}>"


class Suporte(Base):
    __tablename__='suporte'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    name=Column(String(80), nullable=False, unique=True)
    

    def __repr__(self):
        return f"<Suporte name={self.name}>"


class Acervo(Base):
    __tablename__='acervo'
    id=Column(Integer(), primary_key=True, autoincrement=True)
    name=Column(String(80), nullable=False)
    localidade=Column(String(80), nullable=False)
    cidade=Column(String(80), nullable=False)
    estado=Column(String(80), nullable=False)
    data_created=Column(String(40), nullable=False)
    origem=Column(String(80), nullable=False)

    # Foreign key to link Users (refers o primary key of the user)
    autor_id = Column(Integer, ForeignKey('autor.id'))
    

    # Foreign key to link tipo de Midia
    tipo_id = Column(Integer, ForeignKey("tipo.id"))
    tipo = relationship("Midia", backref=backref("tipo", uselist=False))

    # Foreign key to link tipo de suporte
    suporte_id = Column(Integer, ForeignKey("suporte.id"))
    suporte = relationship("Suporte", backref=backref("suporte", uselist=False))

    protagonistas = relationship('Protagonista', secondary=acervo_protagonista, backref='acervos'  )


    def __repr__(self):
        return f"<Acervo name={self.name} localidade={self.localidade}>"




    
