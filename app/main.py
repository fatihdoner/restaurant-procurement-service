import os
import re
import shutil
import threading
import uuid

from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db import get_session, Menu, Restaurant, RestaurantBrand, Product, MenuSection, MenuItem, Ingredient, IngredientAlias, MenuItemIngredient, SessionLocal

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
        q = q.filter(Restaurant.district == district)
    rows = q.all()
    return [{"restaurant_id": r.id, "name": r.name, "city": r.city, "district": r.district} for r in rows]


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
        existing = db.query(Product).filter_by(brand=brand, name=name).first()
        if existing:
            continue
        product = Product(name=name, brand=brand)
        db.add(product)
        db.flush()
        created.append({"product_id": product.id, "name": product.name})
    db.commit()
    return {"brand": brand, "created_count": len(created), "products": created}


@app.get("/products")
def list_products(brand: str = "", db: Session = Depends(get_session)):
    q = db.query(Product)
    if brand:
        q = q.filter(Product.brand == brand)
    rows = q.all()
    return [{"product_id": p.id, "name": p.name, "brand": p.brand} for p in rows]


@app.get("/products/brands")
def list_brands(db: Session = Depends(get_session)):
    rows = db.query(Product.brand).distinct().all()
    return [r[0] for r in rows]


# ------------------------------------------------------------------
# Menu yukleme
# ------------------------------------------------------------------
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


# ------------------------------------------------------------------
# Raporlar -- bolge filtreli, tek istekle
# ------------------------------------------------------------------
INGREDIENT_FREQ_SQL = " ".join([
    "select i.canonical_name,",
    "count(distinct r.id) as restaurant_count,",
    "count(distinct mi.id) as menu_item_count,",
    "count(mii.id) as total_mentions",
    "from menu_item_ingredients mii",
    "join ingredients i on i.id = mii.ingredient_id",
    "join menu_items mi on mi.id = mii.menu_item_id",
    "join menu_sections ms on ms.id = mi.menu_section_id",
    "join menus m on m.id = ms.menu_id",
    "join restaurants r on r.id = m.restaurant_id",
    "{where_sql}",
    "group by i.canonical_name",
    "order by restaurant_count desc, total_mentions desc",
])


@app.get("/reports/ingredient-frequency")
def ingredient_frequency_report(district: str = "", city: str = "", db: Session = Depends(get_session)):
    # Belirli bir bolgedeki (veya tum) restoranlarin ingredient frekans tablosu.
    where_clauses = []
    params = {}
    if district:
        where_clauses.append("r.district = :district")
        params["district"] = district
    if city:
        where_clauses.append("r.city = :city")
        params["city"] = city
    where_sql = ("where " + " and ".join(where_clauses)) if where_clauses else ""

    sql = text(INGREDIENT_FREQ_SQL.format(where_sql=where_sql))
    rows = db.execute(sql, params).fetchall()
    return [
        {"canonical_name": r[0], "restaurant_count": r[1], "menu_item_count": r[2], "total_mentions": r[3]}
        for r in rows
    ]


STOP_WORDS = {"gr", "ve", "ile", "250", "500"}


def _tokens(s: str):
    s = s.strip().lower().replace("i̇", "i")
    toks = re.findall(r"[a-zçğıöşü]+", s)
    return [t for t in toks if t not in STOP_WORDS and len(t) > 2]


def _token_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if len(a) >= 6 and len(b) >= 6 and (a.startswith(b) or b.startswith(a)):
        return True
    return False


def _classify(product_name: str, ing_rows):
    # ing_rows: [(canonical_name, restaurant_count, total_mentions), ...]
    p_tok = _tokens(product_name)
    best_direct = None
    best_category = (0, None, 0, 0)
    for name, rest_count, mentions in ing_rows:
        n_tok = _tokens(name)
        if not p_tok or not n_tok:
            continue
        shorter, longer = (p_tok, n_tok) if len(p_tok) <= len(n_tok) else (n_tok, p_tok)
        if all(any(_token_match(s, l) for l in longer) for s in shorter):
            if best_direct is None or mentions > best_direct[2]:
                best_direct = (name, rest_count, mentions)
            continue
        overlap = sum(1 for s in p_tok if any(_token_match(s, l) for l in n_tok))
        if overlap > 0 and overlap > best_category[0]:
            best_category = (overlap, name, rest_count, mentions)
    if best_direct:
        return "DIRECT MATCH", best_direct[0], best_direct[1], best_direct[2]
    if best_category[1]:
        return "CATEGORY MATCH", best_category[1], best_category[2], best_category[3]
    return "DEVELOPMENT OPPORTUNITY", None, 0, 0


@app.get("/reports/product-matching")
def product_matching_report(brand: str, district: str = "", city: str = "", db: Session = Depends(get_session)):
    # Herhangi bir markanin (brand parametresiyle) urun portfoyunu, belirli bir
    # bolgedeki restoranlarin ingredient verisiyle eslestirir. Kelime bazli
    # (fuzzy) eslestirme -- semantik degildir, CATEGORY MATCH satirlari
    # manuel kontrol edilmelidir.
    products = db.query(Product).filter_by(brand=brand).all()
    if not products:
        raise HTTPException(404, f"'{brand}' markasina ait urun bulunamadi. Once /products/bulk ile ekleyin.")

    freq = ingredient_frequency_report(district=district, city=city, db=db)
    ing_rows = [(r["canonical_name"], r["restaurant_count"], r["total_mentions"]) for r in freq]

    results = []
    for product in products:
        match_type, match_name, rest_count, mentions = _classify(product.name, ing_rows)
        results.append({
            "urun": product.name,
            "eslesme_tipi": match_type,
            "en_yakin_ingredient": match_name,
            "kac_restoranda_geciyor": rest_count,
            "toplam_kullanim": mentions,
        })

    order = {"DIRECT MATCH": 0, "CATEGORY MATCH": 1, "DEVELOPMENT OPPORTUNITY": 2}
    results.sort(key=lambda x: (order[x["eslesme_tipi"]], -x["kac_restoranda_geciyor"], -x["toplam_kullanim"]))
    return {"brand": brand, "district": district or "tumu", "results": results}


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
        return best_name, round(best_score * 100, 2)
    return raw.strip().title(), 0.0


@app.post("/import/csv-menu")
def import_csv_menu(payload: dict, db: Session = Depends(get_session)):
    city = payload.get("city", "")
    district = payload.get("district", "")
    restaurant_type = payload.get("restaurant_type", "")
    rows = payload.get("rows", [])

    existing_ingredients = [i.canonical_name for i in db.query(Ingredient).all()]
    pool = list(existing_ingredients)
    alias_cache = {
        a.alias_text: (a.ingredient_id, float(a.confidence_score or 0))
        for a in db.query(IngredientAlias).all()
    }
    ingredient_id_by_name = {i.canonical_name: i.id for i in db.query(Ingredient).all()}

    brands_created = {}
    restaurants_created = {}
    sections_created = {}
    items_count = 0
    mentions_count = 0

    for row in rows:
        marka = str(row.get("marka", "")).strip()
        yemek = str(row.get("yemek", "")).strip()
        icerik = row.get("icerik")
        fiyat = row.get("fiyat")
        if not marka or not yemek:
            continue

        if marka not in brands_created:
            brand = db.query(RestaurantBrand).filter_by(name=marka).first()
            if not brand:
                brand = RestaurantBrand(name=marka, restaurant_type=restaurant_type)
                db.add(brand)
                db.flush()
            brands_created[marka] = brand.id

            restaurant = db.query(Restaurant).filter_by(
                brand_id=brand.id, city=city, district=district
            ).first()
            if not restaurant:
                restaurant = Restaurant(
                    brand_id=brand.id, name=marka, city=city, district=district
                )
                db.add(restaurant)
                db.flush()
            restaurants_created[marka] = restaurant.id

            menu = db.query(Menu).filter_by(
                restaurant_id=restaurant.id, source_file_name="excel-import"
            ).first()
            if not menu:
                menu = Menu(
                    restaurant_id=restaurant.id,
                    source_file_url="excel-import",
                    source_file_name="excel-import",
                    status="completed",
                )
                db.add(menu)
                db.flush()

            section = MenuSection(menu_id=menu.id, name="Menü")
            db.add(section)
            db.flush()
            sections_created[marka] = section.id

        section_id = sections_created[marka]
        price = None
        try:
            if fiyat is not None and str(fiyat).strip() not in ("", "nan"):
                price = float(fiyat)
        except (ValueError, TypeError):
            price = None

        menu_item = MenuItem(
            menu_section_id=section_id,
            name=yemek,
            price=price,
            raw_description_text=str(icerik) if icerik else None,
        )
        db.add(menu_item)
        db.flush()
        items_count += 1

        if not icerik or str(icerik).strip() in ("", "nan"):
            continue

        for raw in _split_ingredients_raw(icerik):
            raw_key = raw.strip().lower()
            if raw_key in alias_cache:
                ingredient_id, confidence = alias_cache[raw_key]
            else:
                canonical, confidence = _fuzzy_normalize_import(raw, pool)
                if canonical not in ingredient_id_by_name:
                    new_ing = Ingredient(canonical_name=canonical)
                    db.add(new_ing)
                    db.flush()
                    ingredient_id_by_name[canonical] = new_ing.id
                    pool.append(canonical)
                ingredient_id = ingredient_id_by_name[canonical]
                db.add(IngredientAlias(
                    ingredient_id=ingredient_id,
                    alias_text=raw_key,
                    source="ai_suggested",
                    confidence_score=confidence,
                ))
                alias_cache[raw_key] = (ingredient_id, confidence)

            db.add(MenuItemIngredient(
                menu_item_id=menu_item.id,
                ingredient_id=ingredient_id,
                raw_text=raw,
                extraction_type="explicit",
                confidence_score=confidence,
            ))
            mentions_count += 1

    db.commit()

    return {
        "restoran_sayisi": len(restaurants_created),
        "urun_sayisi": items_count,
        "ingredient_mention_sayisi": mentions_count,
    }
