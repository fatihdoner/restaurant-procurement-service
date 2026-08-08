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
    "raw_description":
