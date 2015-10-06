#!/usr/bin/env python

import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    stores = relationship('Store', backref='user', cascade="delete")
    toys = relationship('Toy', backref='user', cascade="delete")


class Store(Base):
    __tablename__ = 'store'
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    url = Column(String(250))
    address = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    toys = relationship('Toy', backref='store', cascade="delete")

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'url': self.url,
            'address': self.address,
        }


class Toy(Base):
    __tablename__ = 'toy'
    name = Column(String(250), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(Float)
    age_min = Column(Integer)
    img_url = Column(String(250))
    url = Column(String(250))
    store_id = Column(Integer, ForeignKey('store.id'))
    user_id = Column(Integer, ForeignKey('user.id'))

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'description': self.description,
            'price': self.price,
            'age_min': self.age_min,
            'img_url': self.img_url,
            'url': self.url,
        }


engine = create_engine('sqlite:///toystores.db')
Base.metadata.create_all(engine)
