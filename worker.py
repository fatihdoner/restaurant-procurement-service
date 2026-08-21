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
