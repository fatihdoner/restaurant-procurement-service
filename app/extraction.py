"""Gercek extraction pipeline - worker.py tarafindan cagrilir."""

import json
import os

import anthropic

MODEL = os.environ.get("EXTRACTION_MODEL", "claude-sonnet-5")
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "85"))

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

EXTRACTION_SYSTEM_PROMPT = "\n".join([
    "Sen bir restoran menusu ingredient extraction uzmanisin.",
    "",
    "KURAL (KAYNAGA SADAKAT - IHLAL EDILEMEZ):",
    "- Sadece menu metninde ACIKCA yazan ingredient'leri cikar.",
    "- Menude yazmayan hicbir ingredient'i tahmin edip ekleme.",
    "- Her ingredient icin extraction_type belirt: explicit, inferred, veya unknown.",
    "- explicit olmayan hicbir seyi explicit olarak isaretleme.",
    "",
    "Cikti SADECE asagidaki JSON semasinda bir liste olmali, baska hicbir metin ekleme:",
    "[",
    "  {",
    '    "section": "string",',
    '    "item_name": "string",',
    '    "price": "string|null",',
    '    "weight": "string|null",',
    '    "raw_description": "string",',
    '    "ingredients": [',
    '      {"raw_text": "string", "extraction_type": "explicit|inferred|unknown"}',
    "    ]",
    "  }",
    "]",
])


def get_text_from_response(response) -> str:
    for block in response.content:
        if block.type == "text":
            return block.text
    raise ValueError("Cevapta text blogu bulunamadi")


def extract_menu_page(page_text: str, page_number: int) -> list[dict]:
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=EXTRACTION_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": "Sayfa " + str(page_number) + " metni:\n\n" + page_text}],
    )
    raw = get_text_from_response(response).replace("```json", "").replace("```", "").strip()
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
    prompt = "\n".join([
        'Bir restoran menusunden su ham ingredient ifadesi cikarildi: "' + raw_text + '"',
        "",
        "Asagidaki normalize edilmis (canonical) ingredient adaylarindan hangisi",
        'bu ifadeye karsilik geliyor? Hicbiri uymuyorsa "NEW" de.',
        "",
        "Adaylar: " + str(candidate_ingredients),
        "",
        'Sadece su JSON u dondur: {"canonical_name": "string veya NEW", "confidence": 0-100}',
    ])
    response = client.messages.create(
        model=MODEL,
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = get_text_from_response(response).replace("```json", "").replace("```", "").strip()
    return json.loads(raw)
