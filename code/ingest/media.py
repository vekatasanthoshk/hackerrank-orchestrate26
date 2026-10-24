"""PNG / PDF evidence -> Observations via a vision model, cached on disk.

For every image or PDF the extractor first looks for ``code/cache/media/<file_id>.json``.
On a cache miss it calls Claude (vision) with the prompt in
``code/prompts/media_extraction.md`` and stores the JSON response, so the model
reads each artifact once and later runs are deterministic and free. PDFs are sent
as rendered page images plus their text layer (PyMuPDF) for higher fidelity.

Records whose ``resource_id`` is not printed on the artifact keep their visible
``aliases`` (statement numbers, file names, user references); the identity layer
resolves those aliases through data-catalog links found in system_activity.csv.
"""
import base64
import json
import os
import re

from .common import RESOURCE_RE, SAFE_ID_RE, SYSTEM_CATEGORY, interpret, make_obs, system_for
import ledger

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(HERE, "cache", "media")
PROMPT_PATH = os.path.join(HERE, "prompts", "media_extraction.md")
MODEL = os.environ.get("MEDIA_MODEL", "claude-sonnet-5-5")


def _prompt_parts():
    with open(PROMPT_PATH, encoding="utf-8") as fh:
        text = fh.read()
    system = text.split("## System", 1)[1].split("## User", 1)[0].strip()
    user = text.split("## User", 1)[1].strip()
    return system, user


def _call_vision(path, file_id, origin, captured_at):
    import anthropic  # imported lazily so cached runs need no SDK / key

    client = anthropic.Anthropic()
    system, user = _prompt_parts()
    user = user.replace("{file_path}", os.path.basename(path)).replace("{origin}", origin).replace(
        "{captured_at}", captured_at)
    content = []
    if path.lower().endswith(".pdf"):
        import pymupdf

        with pymupdf.open(path) as doc:
            for page in doc:
                png = page.get_pixmap(dpi=110).tobytes("png")
                content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                                            "data": base64.b64encode(png).decode()}})
            content.append({"type": "text", "text": "Text layer:\n" + "\n".join(p.get_text() for p in doc)})
    else:
        with open(path, "rb") as fh:
            data = base64.b64encode(fh.read()).decode()
        content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}})
    content.append({"type": "text", "text": user})
    resp = client.messages.create(model=MODEL, max_tokens=16000, system=system,
                                  output_config={"effort": "medium"},
                                  messages=[{"role": "user", "content": content}])
    ledger.record("media_extraction", MODEL, resp.usage, file_id)
    if resp.stop_reason == "refusal":
        raise ValueError("model refused")
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON in model answer")
    return json.loads(m.group(0))


# Fields a media record may carry, and their accepted types. Anything else in the
# model's answer (or in a tampered cache file) is dropped before interpretation.
_STR_FIELDS = ("resource_id", "system", "full_name", "email", "phone", "customer_reference", "status",
               "result", "enabled", "restore_allowed", "observed_at", "category")
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
        if clean.get("category") and clean["category"] not in SYSTEM_CATEGORY.values():
            clean["category"] = None
        aliases = rec.get("aliases") if isinstance(rec.get("aliases"), list) else []
        clean["aliases"] = [str(a)[:128] for a in aliases if isinstance(a, (str, int)) and str(a).strip()][:20]
        out.append(clean)
    return out


def extract(path, file_id, origin, captured_at):
    if not SAFE_ID_RE.match(file_id or ""):
        return {"records": [], "error": "unsafe file_id"}
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, f"{file_id}.json")
    if os.path.exists(cache):
        with open(cache, encoding="utf-8") as fh:
            return json.load(fh)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"records": [], "error": "no cache and no ANTHROPIC_API_KEY"}
    try:
        data = _call_vision(path, file_id, origin, captured_at)
    except Exception as exc:  # never cache a failed extraction; the run continues without this file
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
        obs = make_obs(file_id, captured_at, rec.get("observed_at") or captured_at,
                       rid or "", exists, flat, system_id=system, category=rec.get("category") or cat,
                       exposed=exposed, active=active, source="media")
        obs.aliases = set(aliases)
        out.append(obs)
    return out
