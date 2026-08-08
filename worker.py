"""
Worker process — Railway/Render'da AYRI bir servis olarak çalıştırılır
(web servisinden ayrı, çünkü extraction birkaç dakika sürebilir).

Basit DB tabanlı polling kullanıyoruz (Redis/BullMQ gibi ekstra bir
altyapıya MVP ölçeğinde gerek yok). menus.status = 'pending' olan
kayıtları bulur, işler, sonucu yazar.

Çalıştırma: python worker.py
"""

import time
import traceback

import fitz  # PyMuPDF

from app.db import (SessionLocal, Menu, MenuSection, MenuItem, Ingredient,
                     IngredientAlias, MenuItemIngredient, AnalysisRun,
                     ExtractionReview)
from app.extraction import (extract_menu_page, self_check_source_fidelity,
                             normalize_ingredient, MODEL, CONFIDENCE_THRESHOLD)

POLL_INTERVAL_SECONDS = 10


def pdf_to_pages_text(local_pdf_path: str) -> list[str]:
    doc = fitz.open(local_pdf_path)
    return [page.get_text() for page in doc]


def find_or_create_ingredient(db, canonical_name: str, raw_text: str, confidence: float):
    """Basit alias lookup + insert. Production'da bunun yerine pgvector
    similarity search kullanılmalı (bkz. tasarım dokümanı madde 6) —
    burada MVP için exact/alias-table lookup yeterli."""
    alias = db.query(IngredientAlias).filter_by(alias_text=raw_text.strip().lower()).first()
    if alias:
        return alias.ingredient_id, alias.confidence_score

    ingredient = db.query(Ingredient).filter_by(canonical_name=canonical_name).first()
    if not ingredient:
        ingredient = Ingredient(canonical_name=canonical_name)
        db.add(ingredient)
        db.flush()

    db.add(IngredientAlias(
        ingredient_id=ingredient.id,
        alias_text=raw_text.strip().lower(),
        source="ai_suggested",
        confidence_score=confidence,
    ))
    return ingredient.id, confidence


def process_menu(db, menu: Menu):
    run = AnalysisRun(menu_id=menu.id, status="running", model_version=MODEL, triggered_by="upload")
    db.add(run)
    menu.status = "processing"
    db.commit()

    try:
        pages = pdf_to_pages_text(menu.source_file_url)  # local path veya indirilmiş dosya
        section_cache = {}  # section adı -> MenuSection.id

        for page_number, page_text in enumerate(pages, start=1):
            if not page_text.strip():
                continue  # boş sayfa (görsel ağırlıklı olabilir) — v2'de vision fallback eklenecek

            items = extract_menu_page(page_text, page_number)

            for item in items:
                item = self_check_source_fidelity(item)

                section_name = item.get("section") or "Genel"
                if section_name not in section_cache:
                    section = MenuSection(menu_id=menu.id, name=section_name)
                    db.add(section)
                    db.flush()
                    section_cache[section_name] = section.id

                menu_item = MenuItem(
                    menu_section_id=section_cache[section_name],
                    name=item["item_name"],
                    price=_parse_price(item.get("price")),
                    raw_description_text=item.get("raw_description"),
                    page_number=page_number,
                )
                db.add(menu_item)
                db.flush()

                for ing in item["ingredients"]:
                    candidates = [i.canonical_name for i in db.query(Ingredient).limit(20)]
                    norm = normalize_ingredient(ing["raw_text"], candidates)
                    canonical_name = norm["canonical_name"]
                    confidence = norm["confidence"]

                    ingredient_id = None
                    if canonical_name != "NEW":
                        ingredient_id, confidence = find_or_create_ingredient(
                            db, canonical_name, ing["raw_text"], confidence
                        )

                    mii = MenuItemIngredient(
                        menu_item_id=menu_item.id,
                        ingredient_id=ingredient_id,
                        raw_text=ing["raw_text"],
                        extraction_type=ing["extraction_type"],
                        confidence_score=confidence,
                    )
                    db.add(mii)
                    db.flush()

                    if confidence < CONFIDENCE_THRESHOLD:
                        db.add(ExtractionReview(
                            menu_item_ingredient_id=mii.id,
                            suggested_value=ing["raw_text"],
                            confidence_score=confidence,
                            status="pending",
                        ))

            db.commit()

        menu.status = "completed"
        run.status = "completed"
        db.commit()

    except Exception:
        db.rollback()
        menu.status = "failed"
        run.status = "failed"
        db.commit()
        traceback.print_exc()


def _parse_price(price_str):
    if not price_str:
        return None
    digits = "".join(c for c in str(price_str) if c.isdigit() or c == ".")
    return float(digits) if digits else None


def main_loop():
    print(f"Worker başladı. Model: {MODEL}. Poll interval: {POLL_INTERVAL_SECONDS}s")
    while True:
        db = SessionLocal()
        try:
            pending = db.query(Menu).filter_by(status="pending").first()
            if pending:
                print(f"İşleniyor: menu_id={pending.id}")
                process_menu(db, pending)
            else:
                time.sleep(POLL_INTERVAL_SECONDS)
        finally:
            db.close()


if __name__ == "__main__":
    main_loop()
