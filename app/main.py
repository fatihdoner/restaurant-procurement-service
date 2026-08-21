import os
import re
import shutil
import threading
import uuid

from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_session, Menu, Restaurant, RestaurantBrand, Product, MenuSection, MenuItem, Ingredient, IngredientAlias, MenuItemIngredient, ExtractionReview, SessionLocal

app = FastAPI(title="Restaurant Procurement Intelligence Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/data/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.on_event("startup")
def start_worker_thread():
    if os.getenv("WORKER_ENABLED", "true").lower() == "true":
        from worker import main_loop
        threading.Thread(target=main_loop, daemon=True).start()


@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------------
# Restoran yonetimi
# ------------------------------------------------------------------
@app.post("/restaurants")
def create_restaurant(
    name: str,
    brand_name: str,
    city: str = "",
    district: str = "",
    restaurant_type: str = "",
    db: Session = Depends(get_session),
):
    # Tek cagriyla restoran + (gerekirse) marka olusturur.
    # Ayni brand_name daha once varsa yeniden kullanir

# ------------------------------------------------------------------
# Urun portfoyu yonetimi (Yayla veya herhangi baska bir marka)
# ------------------------------------------------------------------
@app.post("/products")
def create_product(name: str, brand: str, sub_category: str = "", db: Session = Depends(get_session)):
    product = Product(name=name, brand=brand, sub_category=sub_category)
    db.add(product)
    db.commit()
    db.refresh(product)
    return {"product_id": product.id, "name": product.name, "brand": product.brand}


@app.post("/products/bulk")
def create_products_bulk(brand: str, names: list[str], db: Session = Depends(get_session)):
    # Tek cagriyla bir markanin tum urun listesini ekler.
    # Ornek govde: {"brand": "Yayla", "names": ["BASMATİ PİRİNÇ", "CHİA", ...]}
    created = []
    for name in names:
        existing =

from difflib import SequenceMatcher

FUZZY_IMPORT_THRESHOLD = 0.82


def _split_ingredients_raw(desc: str):
    desc = str(desc).strip()
    desc = re.sub(r"\s*(ile\.?)$", "", desc, flags=re.IGNORECASE)
    desc = desc.replace(";", ",")
    parts = re.split(r",|\.", desc)
    return [p.strip() for p in parts if p.strip() and len(p.strip()) > 1]


def _fuzzy_normalize_import(raw: str, pool: list):
    raw_norm = raw.strip().lower()
    best_score, best_name = 0.0, None
    for name in pool:
        score = SequenceMatcher(None, raw_norm, name.lower()).ratio()
        if score > best_score:
            best_score, best_name = score, name
    if best_score >= FUZZY_IMPORT_THRESHOLD:
        return best_name,
