"""
Worker process - Railway'de web servisiyle ayni process icinde,
background thread olarak calisir.
"""

import os
import time
import traceback
from difflib import SequenceMatcher

import fitz

from app.db import (SessionLocal, Menu, MenuSection, MenuItem, Ingredient,
                     IngredientAlias, MenuItemIngredient, AnalysisRun,
                     ExtractionReview)
from app.extraction import (extract_menu_page, self_check_source_fidelity,
                             MODEL, CONFIDENCE_THRESHOLD)

POLL_INTERVAL_SECONDS = 10
FUZZY_MATCH_THRESHOLD = 0.82


def pdf_to_pages_text(local_pdf_path: str) -> list[str]:
    doc = fitz.open(local_pdf_path)
    return [page.get_text() for page in doc]


def fuzzy_normalize(raw_text: str, canonical_names: list[str]):
    raw_norm = raw_text.strip().lower()
    best_match = None
    best_score = 0.0
    for name in canonical_names:
        score = SequenceMatcher(None, raw_norm, name.lower()).ratio()
        if score > best_score:
            best_score = score
            best_match = name
    if best_match and best_score >= FUZZY_MATCH_THRESHOLD:
        return best_match, round(best_score * 100, 2)
    return raw_text.strip().title(), 0.0


def find_or_create_ingredient(db, raw_text: str):
    alias = db.query(IngredientAlias).filter_by(alias_text=raw_text.strip().lower()).first()
    if alias:
        return alias.ingredient_id, float(alias.confidence_score)

    if os.getenv("INGREDIENT_WRITE_MODE", "normal") == "migration_safe":
        return None, 0.0

    existing = db.query(Ingredient).all()
    canonical_name, confidence = fuzzy_normalize(raw_text, [i.canonical_name for i in existing])

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
        pages = pdf_to_pages_text(menu.source_file_url)
        section_cache = {}

        for page_number, page_text in enumerate(pages, start=1):
            if not page_text.strip():
                continue

            try:
                items = extract_menu_page(page_text, page_number)
            except Exception as e:
                print(f"Sayfa {page_number} atlandi, hata: {e}")
                continue

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
                    try:
                        ingredient_id, confidence = find_or_create_ingredient(db, ing["raw_text"])
                    except Exception as e:
                        print(f"Normalization atlandi ({ing['raw_text']}): {e}")
                        ingredient_id, confidence = None, 0.0

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
    print(f"Worker basladi. Model: {MODEL}. Poll interval: {POLL_INTERVAL_SECONDS}s")
    while True:
        db = SessionLocal()
        try:
            pending = db.query(Menu).filter_by(status="pending").first()
            if pending:
                print(f"Isleniyor: menu_id={pending.id}")
                process_menu(db, pending)
            else:
                time.sleep(POLL_INTERVAL_SECONDS)
        except Exception as e:
            print(f"main_loop hatasi (worker devam ediyor): {e}")
            time.sleep(POLL_INTERVAL_SECONDS)
        finally:
            db.close()


if __name__ == "__main__":
    main_loop()
