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
    status = Column(Text, default="pending")
    uploaded_at = Column(DateTime, default=datetime.utcnow)


class MenuSection(Base):
    __tablename__ = "menu_sections"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    menu_id = Column(UUID(as_uuid=False), ForeignKey("menus.id"))
    name = Column(Text, nullable=False)
    display_order = Column(Integer)


class MenuItem(Base):
    __tablename__ = "menu_items"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    menu_section_id = Column(UUID(as_uuid=False), ForeignKey("menu_sections.id"))
    name = Column(Text, nullable=False)
    price = Column(Numeric)
    weight_grams = Column(Numeric)
    raw_description_text = Column(Text)
    page_number = Column(Integer)


class Ingredient(Base):
    __tablename__ = "ingredients"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    canonical_name = Column(Text, nullable=False, unique=True)
    procurement_category_id = Column(UUID(as_uuid=False), ForeignKey("procurement_categories.id"))


class ProcurementCategory(Base):
    __tablename__ = "procurement_categories"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    name = Column(Text, nullable=False, unique=True)


class IngredientAlias(Base):
    __tablename__ = "ingredient_aliases"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    ingredient_id = Column(UUID(as_uuid=False), ForeignKey("ingredients.id"))
    alias_text = Column(Text, nullable=False, unique=True)
    source = Column(Text, nullable=False)
    confidence_score = Column(Numeric)


class MenuItemIngredient(Base):
    __tablename__ = "menu_item_ingredients"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    menu_item_id = Column(UUID(as_uuid=False), ForeignKey("menu_items.id"))
    ingredient_id = Column(UUID(as_uuid=False), ForeignKey("ingredients.id"), nullable=True)
    raw_text = Column(Text, nullable=False)
    extraction_type = Column(Text, nullable=False)
    confidence_score = Column(Numeric)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    menu_id = Column(UUID(as_uuid=False), ForeignKey("menus.id"))
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(Text, default="running")
    model_version = Column(Text)
    triggered_by = Column(Text)


class ExtractionReview(Base):
    __tablename__ = "extraction_reviews"
    id = Column(UUID(as_uuid=False), primary_key=True, default=uid)
    menu_item_ingredient_id = Column(UUID(as_uuid=False), ForeignKey("menu_item_ingredients.id"), nullable=True)
    ingredient_alias_id = Column(UUID(as_uuid=False), ForeignKey("ingredient_aliases.id"), nullable=True)
    suggested_value = Column(Text, nullable=False)
    confidence_score = Column(Numeric)
    status = Column(Text, default="pending")


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
