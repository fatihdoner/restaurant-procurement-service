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
    # Tek cagriyla restoran + (gerekirse)
