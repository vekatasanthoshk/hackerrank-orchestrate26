"""PNG / PDF evidence -> Observations via a vision model, cached on disk.

For every image or PDF the extractor first looks for ``code/cache/media/<file_id>.json``.
On a cache miss it calls Claude (vision) with the prompt in
``code/prompts/media_extraction.md`` and stores the JSON response, so the model
reads each artifact once and later runs are deterministic and free. PDFs are sent
as native document blocks (page images + text layer); images above the API size
limits are downscaled with PyMuPDF first.

Records whose ``resource_id`` is not printed on the artifact keep their visible
``aliases`` (statement numbers, file names, user references); the identity layer
resolves those aliases through data-catalog links found in system_activity.csv.
"""
import base64
import json
import os
import re

from .common import RESOURCE_RE, SAFE_ID_RE, SYSTEM_CATEGORY, interpret, make_obs, system_for
import keys
import ledger

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(HERE, "cache", "media")
PROMPT_PATH = os.path.join(HERE, "prompts", "media_extraction.md")
MODEL = os.environ.get("MEDIA_MODEL", "claude-sonnet-5-5")
MANUAL_DIR = os.path.join(HERE, "cache", "media_manual")
# set by `main.py --refresh-media`: re-extract every artifact with the vision model even if
# a cached extraction exists (the previous cache file is kept in cache/media_manual/ once,
# so evaluation/compare_media.py can diff the two extractions)
REFRESH = False
ERRORS = []  # failed or skipped extractions; ingest.load_observations turns them into run warnings


def _prompt_parts():
    with open(PROMPT_PATH, encoding="utf-8") as fh:
        text = fh.read()
    system = text.split("## System", 1)[1].split("## User", 1)[0].strip()
    user = text.split("## User", 1)[1].strip()
    return system, user


MAX_IMAGE_BYTES = 3_700_000   # 5 MB API limit per image, measured on the base64 text (x4/3)
MAX_IMAGE_EDGE = 8000          # API limit; the model itself reads up to 2576 px on the long edge
IMAGE_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}


def _image_bytes(path):
    """Image bytes within the API limits (PyMuPDF halves an oversized image until it fits)."""
    with open(path, "rb") as fh:
        data = fh.read()
    import struct

    w, h = struct.unpack(">II", data[16:24]) if data[:8] == b"\x89PNG\r\n\x1a\n" else (0, 0)
    if len(data) <= MAX_IMAGE_BYTES and max(w, h) <= MAX_IMAGE_EDGE:
        return data, IMAGE_TYPES.get(os.path.splitext(path)[1].lower(), "image/png")
    import pymupdf

    pix = pymupdf.Pixmap(path)
    while len(pix.tobytes("png")) > MAX_IMAGE_BYTES or max(pix.width, pix.height) > MAX_IMAGE_EDGE:
        pix.shrink(1)
    return pix.tobytes("png"), "image/png"


def _call_vision(path, file_id, origin, captured_at, client=None):
    client = client or keys.client()  # SDK imported lazily so cached runs need no SDK / key
    system, user = _prompt_parts()
    user = user.replace("{file_path}", os.path.basename(path)).replace("{origin}", origin).replace(
        "{captured_at}", captured_at)
    if path.lower().endswith(".pdf"):
        # PDFs go in natively: the model sees every page image and the text layer
        with open(path, "rb") as fh:
            block = {"type": "document", "source": {"type": "base64", "media_type": "application/pdf",
                                                    "data": base64.standard_b64encode(fh.read()).decode()}}
    else:
        data, media_type = _image_bytes(path)
        block = {"type": "image", "source": {"type": "base64", "media_type": media_type,
                                             "data": base64.standard_b64encode(data).decode()}}
    # fallbacks="default": a request the safety classifiers decline is re-run server-side on the
    # recommended fallback model instead of failing (the served model is what the ledger records)
    resp = client.beta.messages.create(model=MODEL, max_tokens=16000, system=system,
                                       output_config={"effort": "medium"},
                                       betas=["server-side-fallback-2026-07-01"], fallbacks="default",
                                       messages=[{"role": "user", "content": [block, {"type": "text", "text": user}]}])
    ledger.record("media_extraction", getattr(resp, "model", None) or MODEL, resp.usage, file_id)
    if resp.stop_reason == "refusal":
        details = getattr(resp, "stop_details", None)
        raise ValueError(f"model refused ({getattr(details, 'category', None) or 'no category'})")
    if resp.stop_reason == "max_tokens":
        raise ValueError("answer truncated at max_tokens")
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON in model answer")
    return json.loads(m.group(0))


# Fields a media record may carry, and their accepted types. Anything else in the
# model's answer (or in a tampered cache file) is dropped before interpretation.
_STR_FIELDS = ("resource_id", "system", "full_name", "email", "phone", "customer_reference", "status",
               "result", "enabled", "restore_allowed", "observed_at", "file_name", "detail_visible")
_KNOWN_SYSTEMS = set(SYSTEM_CATEGORY)
_MAX_RECORDS = 200


def validate_records(data):
    """Keep only well-formed records from an extraction (model output is untrusted)."""
    out = []
    recs = data.get("records") if isinstance(data, dict) else None
    if not isinstance(recs, list):
        return out
    for rec in recs[:_MAX_RECORDS]:
        if not isinstance(rec, dict):
            continue
        clean = {}
        for k in _STR_FIELDS:
            v = rec.get(k)
            if isinstance(v, bool):
                v = "true" if v else "false"
            if v is None or isinstance(v, (str, int, float)):
                clean[k] = None if v is None else str(v)[:256]
        rid = (clean.get("resource_id") or "").strip()
        if rid and not RESOURCE_RE.match(rid):
            continue  # not a resource id the systems use: never trust it
        clean["resource_id"] = rid or None
        if clean.get("system") and clean["system"] not in _KNOWN_SYSTEMS:
            clean["system"] = system_for(rid) if rid else None
        aliases = rec.get("aliases") if isinstance(rec.get("aliases"), list) else []
        clean["aliases"] = [str(a)[:128] for a in aliases if isinstance(a, (str, int)) and str(a).strip()][:20]
        out.append(clean)
    return out


def extract(path, file_id, origin, captured_at):
    if not SAFE_ID_RE.match(file_id or ""):
        return {"records": [], "error": "unsafe file_id"}
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, f"{file_id}.json")
    if REFRESH and keys.api_key() and os.path.exists(cache):
        os.makedirs(MANUAL_DIR, exist_ok=True)
        keep = os.path.join(MANUAL_DIR, f"{file_id}.json")
        if not os.path.exists(keep):
            os.replace(cache, keep)
        else:
            os.remove(cache)
    if os.path.exists(cache):
        with open(cache, encoding="utf-8") as fh:
            return json.load(fh)
    if not keys.api_key():
        ERRORS.append(f"{file_id}: no cached extraction and no API key; artifact skipped")
        return {"records": [], "error": "no cache and no API key"}
    try:
        data = _call_vision(path, file_id, origin, captured_at)
    except Exception as exc:  # never cache a failed extraction
        ERRORS.append(f"{file_id}: vision extraction failed ({type(exc).__name__}: {exc})")
        manual = os.path.join(MANUAL_DIR, f"{file_id}.json")
        if os.path.exists(manual):  # keep the run complete with the earlier transcription (warned)
            with open(manual, encoding="utf-8") as fh:
                return json.load(fh)
        return {"records": [], "error": f"{type(exc).__name__}: {exc}"}
    data = {"file_id": file_id, "records": validate_records(data), "extracted_by": MODEL}
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return data


def media_observations(path, file_id, origin, captured_at):
    data = extract(path, file_id, origin, captured_at)
    out = []
    for rec in validate_records(data):
        rid = rec.get("resource_id")
        aliases = [a for a in rec.get("aliases") or [] if a]
        if not rid and not aliases:
            continue
        system = rec.get("system") or (system_for(rid) if rid else None)
        flat = {k: v for k, v in rec.items() if k not in ("aliases",)}
        for k in ("enabled", "restore_allowed"):
            if isinstance(flat.get(k), bool):
                flat[k] = "true" if flat[k] else "false"
        exists, exposed, active, cat = interpret(system, flat)
        if str(flat.get("detail_visible") or "").lower() == "false":
            exposed = None  # only referenced: the artifact cannot show whether identifiers remain
        obs = make_obs(file_id, captured_at, rec.get("observed_at") or captured_at,
                       rid or "", exists, flat, system_id=system, category=cat,
                       exposed=exposed, active=active, source="media")
        obs.aliases = set(aliases)
        out.append(obs)
    return out
