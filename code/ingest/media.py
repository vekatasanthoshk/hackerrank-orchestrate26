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

from .common import interpret, make_obs, system_for
import ledger

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(HERE, "cache", "media")
PROMPT_PATH = os.path.join(HERE, "prompts", "media_extraction.md")
MODEL = os.environ.get("MEDIA_MODEL", "claude-sonnet-5-5")


def _prompt_parts():
    text = open(PROMPT_PATH, encoding="utf-8").read()
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

        doc = pymupdf.open(path)
        for page in doc:
            png = page.get_pixmap(dpi=110).tobytes("png")
            content.append({"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                                        "data": base64.b64encode(png).decode()}})
        content.append({"type": "text", "text": "Text layer:\n" + "\n".join(p.get_text() for p in doc)})
    else:
        data = base64.b64encode(open(path, "rb").read()).decode()
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


def extract(path, file_id, origin, captured_at):
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, f"{file_id}.json")
    if os.path.exists(cache):
        return json.load(open(cache, encoding="utf-8"))
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"records": [], "error": "no cache and no ANTHROPIC_API_KEY"}
    try:
        data = _call_vision(path, file_id, origin, captured_at)
    except Exception as exc:  # never cache a failed extraction; the run continues without this file
        return {"records": [], "error": f"{type(exc).__name__}: {exc}"}
    data["extracted_by"] = MODEL
    json.dump(data, open(cache, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    return data


def media_observations(path, file_id, origin, captured_at):
    data = extract(path, file_id, origin, captured_at)
    out = []
    for rec in data.get("records", []):
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
