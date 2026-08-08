import os
import shutil
import threading
import uuid

from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.db import get_session, Menu, Restaurant

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


@app.post("/restaurants/{restaurant_id}/menus")
async def upload_menu(restaurant_id: str, file: UploadFile, db: Session = Depends(get_session)):
    restaurant = db.query(Restaurant).get(restaurant_id)
    if not restaurant:
        raise HTTPException(404, "Restaurant bulunamadı")

    file_id = str(uuid.uuid4())
    local_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(local_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    menu = Menu(
        restaurant_id=restaurant_id,
        source_file_url=local_path,
        source_file_name=file.filename,
        status="pending",
    )
    db.add(menu)
    db.commit()
    db.refresh(menu)

    return {"menu_id": menu.id, "status": menu.status}


@app.get("/menus/{menu_id}/status")
def menu_status(menu_id: str, db: Session = Depends(get_session)):
    menu = db.query(Menu).get(menu_id)
    if not menu:
        raise HTTPException(404, "Menu bulunamadı")
    return {"menu_id": menu.id, "status": menu.status}
