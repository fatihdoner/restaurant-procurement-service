"""
Gerçek extraction pipeline — worker.py tarafından çağrılır.
"""

import json
import os

import anthropic

MODEL = os.environ.get("EXTRACTION_MODEL", "claude-sonnet-5")
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "85"))

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

EXTRACTION_SYSTEM_PROMPT = """
Sen bir restoran menüsü ingredient extraction uzmanısın.

KURAL (KAYNAĞA SADAKAT — İHLAL EDİLEMEZ):
- Sadece menü metninde AÇIKÇA yazan ingredient'leri çıkar.
- Menüde yazmayan hiçbir ingredient'i tahmin edip ekleme.
- Her ingredient için extraction_type belirt: "explicit", "inferred", veya "unknown".
- explicit olmayan hiçbir şeyi explicit olarak işaretleme.

Çıktı SADECE şu JSON şemasında bir liste olmalı, başka hiçbir metin ekleme:
[
  {
    "section": "string",
    "item_name": "string",
    "price": "string|null",
    "weight": "string|null",
    "raw_description": "string",
    "ingredients": [
      {"raw_text": "string", "extraction_type": "explicit|inferred|unknown"}
    ]
  }
]
"""


def extract_menu_page(page_text: str, page_number: int) -> list[dict]:
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=EXTRACTION_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Sayfa {page_number} metni:\n\n{page_text}"}],
    )
    raw = response.content[0].text.replace("```json", "").replace("```", "").strip()
    items = json.loads(raw)
    for item in items:
        item["page_number"] = page_number
    return items


def self_check_source_fidelity(item: dict) -> dict:
    desc_lower = (item.get("raw_description") or "").lower()
    for ing in item["ingredients"]:
        if ing["extraction_type"] == "explicit" and ing["raw_text"].lower() not in desc_lower:
            ing["extraction_type"] = "inferred"
            ing["fidelity_check"] = "failed_downgraded"
    return item


def normalize_ingredient(raw_text: str, candidate_ingredients: list[str]) -> dict:
    prompt = f"""
    Bir restoran menüsünden şu ham ingredient ifadesi çıkarıldı: "{raw_text}"

    Aşağıdaki normalize edilmiş (canonical) ingredient adaylarından hangisi
    bu ifadeye karşılık geliyor? Hiçbiri uymuyorsa "NEW" de.

    Adaylar: {candidate_ingredients}

    Sadece şu JSON'u döndür: {{"canonical_name": "string veya NEW", "confidence": 0-100}}
    """
    response = client.messages.create(
        model=MODEL,
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = response.content[0].text.replace("```json", "").replace("```", "").strip()
    return json.loads(raw)
