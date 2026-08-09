import os
import re
import shutil
import threading
import uuid

from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_session, Menu, Restaurant, RestaurantBrand, SessionLocal

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
    from worker import main_loop
    threading.Thread(target=main_loop, daemon=True).start()


@app.get("/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------------------
# Restoran yonetimi -- artik SQL konsoluna gerek yok
# ------------------------------------------------------------------
@app.post("/restaurants")
def create_restaurant(
    name: str,
    brand_name: str,
    city: str = "",
    district: str = "",
    restaurant_type: str = "",
    source_platform: str = "",
    db: Session = Depends(get_session),
):
    # Tek cagriyla restoran + (gerekirse) marka olusturur.
    # Ayni brand_name daha once varsa yeniden kullanir (zincir sube ekleme).
    brand = db.query(RestaurantBrand).filter_by(name=brand_name).first()
    if not brand:
        brand = RestaurantBrand(name=brand_name, restaurant_type=restaurant_type)
        db.add(brand)
        db.flush()

    restaurant = Restaurant(brand_id=brand.id, name=name, city=city, district=district)
    db.add(restaurant)
    db.commit()
    db.refresh(restaurant)

    return {
        "restaurant_id": restaurant.id,
        "brand_id": brand.id,
        "name": restaurant.name,
        "district": restaurant.district,
    }


@app.get("/restaurants")
def list_restaurants(district: str = "", db: Session = Depends(get_session)):
    q = db.query(Restaurant)
    if district:
        q =
