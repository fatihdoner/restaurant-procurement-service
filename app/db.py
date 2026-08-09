import os
import uuid
from datetime import datetime

from sqlalchemy import (Column, String, Text, Numeric, Integer, Boolean,
                         ForeignKey, DateTime, create_engine)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def uid():
    return str(uuid.uuid4())


class RestaurantBrand(Base):
    __tablename__ = "restaurant_brands"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    name = Column(Text, nullable=False)
    restaurant_type = Column(Text)
    category = Column(Text)
    central_purchasing = Column(Boolean)


class Restaurant(Base):
    __tablename__ = "restaurants"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    brand_id = Column(UUID(as_uuid=False), ForeignKey("restaurant_brands.id"))
    name = Column(Text, nullable=False)
    city = Column(Text)
    district = Column(Text)
    address = Column(Text)
    latitude = Column(Numeric)
    longitude = Column(Numeric)


class Menu(Base):
    __tablename__ = "menus"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    restaurant_id = Column(UUID(as_uuid=False), ForeignKey("restaurants.id"))
    source_file_url = Column(Text, nullable=False)
    source_file_name = Column(Text)
    version_number = Column(Integer, default=1)
    status =
