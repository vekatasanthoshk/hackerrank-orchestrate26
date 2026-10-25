"""Deletion-vs-not intent classifier: Claude Haiku + disk cache + multilingual rule layer.

* With an API key set (``ANTHROPIC_API_KEY`` or ``AUDIT_ANTHROPIC_API_KEY``, see keys.py),
  each distinct request text is classified once by
  ``claude-haiku-5-5`` (prompt: prompts/intent_classification.md, effort low, JSON-schema
  output) and cached in cache/intent_cache.json; usage is written to the run ledger.
* Without a key (or on an API error) the deterministic rule classifier below is used.

Rule layer. The cue lists are written per request category from the task definition
(problem_statement.md: access, export, correction, marketing opt-out, login help,
billing), not from individual request texts, in the six languages the requests use:

  1. KEEP cues - the customer explicitly keeps the account or says this is not a
     deletion ("do not close", "not asking for deletion", "sin borrar ...").
     They win over everything: a destructive action needs an explicit request.
  2. DELETE cues - erase / delete / close the account, right to erasure ...
     A removal that is scoped to marketing lists is an opt-out, not a deletion.
  3. Category cues (access, export, correction, opt-out, login, billing) decide a
     text that has no deletion cue: it is NOT_DELETION either way, the category
     only explains why.

Prompt injection. Request text is untrusted. Instruction-like segments (role tags such
as "SYSTEM:", "ignore previous instructions", "answer DELETION", a forged closing tag)
are cut out before either layer sees the text. When such markers were present, the
model's answer is not trusted on its own: a disagreement with the rule layer resolves
to the rule layer's answer on the cleaned text, and the case is flagged.
"""
import hashlib
import json
import os
import re

import keys
import ledger

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache", "intent_cache.json")
PROMPT = os.path.join(HERE, "prompts", "intent_classification.md")
MODEL = os.environ.get("INTENT_MODEL", "claude-haiku-5-5")
MAX_TOKENS = 2048  # adaptive thinking counts against it; the answer itself is ~30 tokens

KEEP_CUES = [
    # en
    r"\bkeep (?:the|my) (?:account|profile)", r"\bleave (?:the|my) (?:account|profile)",
    r"\b(?:do not|don't|dont|please don't) (?:close|delete|remove|erase|deactivate)",
    r"\bwithout (?:removing|deleting|erasing|closing)",
    r"(?<!n't )(?<!not )(?<!no )\b(?:want|wish|plan|intend|like) to (?:continue|keep) using",
    r"\bstill (?:want|need|use) (?:the|my|this) (?:account|profile|service)",
    r"\b(?:i'm|i am) not asking (?:for|you to) (?:a |an |any )?(?:delet|eras|clos|remov)",
    r"\bnot (?:a |an )?(?:request|asking|requesting)\b[^.]{0,30}\b(?:delet|eras|remov|clos)",
    # es
    r"\bno (?:cierren|eliminen|borren|cierre|elimine|borre|desactiven)\b", r"\bmantener (?:mi|la) cuenta",
    r"\bsin (?:eliminar|borrar|cerrar)\b",
    # pt
    r"\bn[aã]o (?:excluam|apaguem|fechem|exclua|apague|feche|desativem)\b", r"\bmanter (?:minha|a) conta",
    r"\bsem (?:excluir|apagar|fechar)\b",
    # fr
    r"\bne (?:pas )?(?:supprimer|fermer|effacer)\b", r"\bne (?:supprimez|fermez|effacez) pas\b",
    r"\b(?:conserver|garder) mon compte", r"\bsans (?:supprimer|effacer|fermer)\b",
    # de
    r"\bnicht (?:l[öo]schen|schlie[ßs]en|entfernen)\b", r"\bkonto behalten\b", r"\bohne (?:zu )?l[öo]schen\b",
    # it
    r"\bnon (?:chiudere|cancellare|eliminare|chiudete|cancellate|eliminate)\b", r"\bmantenere il (?:mio )?account\b",
    r"\bsenza (?:cancellare|eliminare|chiudere)\b",
    # ja / ko / zh
    "削除しないで", "退会しない", "アカウントはそのまま", "삭제하지", "탈퇴하지", "계정은 유지", "不要删除", "不要刪除",
    "保留我的帐户", "保留我的帳戶", "保留账户",
]
DELETE_CUES = [
    r"\bdelet", r"\berase\b", r"\berasure\b", r"\beras(?:ed|ing)\b", r"\bremov", r"\bwipe\b", r"\bpurge\b",
    r"\bforget (?:me|about me|my)\b", r"\bget rid of\b", r"\bdisconnect",
    r"\bclos(?:e|ed|ing) (?:my|this|the) (?:account|profile)", r"\bshut (?:down )?(?:my|this|the) (?:account|profile)",
    r"\bshut (?:it|my account|the account) down", r"\b(?:account|profile) (?:is|was) (?:gone|closed)\b",
    r"\bprofile is gone\b", r"\bclean .* out of", r"\bdeactivate and delete",
    r"supprim", r"suppression", r"effac", r"fermer (?:mon|le) compte",                 # fr
    r"elimin", r"borr", r"cancelar (?:mi|la) cuenta", r"cerrar (?:mi|la) cuenta",      # es
    r"exclu", r"apag", r"encerrar (?:minha|a) conta",                                  # pt
    r"l[öo]sch", r"entfern", r"konto schlie[ßs]en",                                    # de
    r"cancell", r"rimuov", r"chiudere (?:il mio|l')account",                          # it
    "削除", "消去", "退会", "삭제", "탈퇴", "删除", "刪除", "注销", "註銷", "销户", "銷戶",  # ja / ko / zh
]
# a removal whose object is a marketing / mailing list is an opt-out (rule: NOT_APPLICABLE)
OPT_OUT_SCOPE = [
    r"\bremov\w* (?:me|my (?:e-?mail|address|number)) from (?:the |your |all )?(?:marketing|mailing|newsletter|promotional|sms)\b",
    r"\b(?:marketing|mailing|newsletter|promotional) lists? only\b",
    r"retir\w* (?:uniquement )?des listes", r"\blistes? (?:marketing|de diffusion)\b",
    r"(?:de|das) listas? de (?:marketing|correo|e-?mail)", r"\bnewsletter[- ]?(?:liste|verteiler)\b",
    "配信停止", "수신 거부", "退订", "退訂",
]
CATEGORY_CUES = {
    "access": [r"\bwhat (?:personal )?(?:information|data) (?:do )?you (?:hold|have|store|keep)", r"\blist of (?:all )?(?:the )?data",
               r"\baccess (?:request|to my data)", r"qu[ée] datos", r"quais dados", r"quelles donn[ée]es",
               r"welche daten", r"quali dati", "どのような個人情報", "어떤 개인정보", "哪些个人信息"],
    "export": [r"\b(?:a )?copy of (?:my|the|all)\b", r"\bexport\b", r"\bdownload\b", r"\bportab", r"\bcsv\b",
               r"copia de", r"c[oó]pia d", r"copie de", r"kopie", r"copia dei", r"descargar", r"baixar",
               r"t[ée]l[ée]charger", r"herunterladen", r"scaricare", "ダウンロード", "コピー", "다운로드", "사본", "下载", "副本"],
    "correction": [r"\bcorrect\b", r"\bcorrection\b", r"\bfix (?:my|the)\b", r"\bupdate (?:my|the)\b", r"\bchange (?:my|the)\b",
                   r"\breplace (?:it|my|the)\b", r"\bspell", r"\btypo\b", r"\bwrong\b", r"\bincorrect\b", r"\boutdated\b",
                   r"corregir", r"actualizar", r"corrigir", r"atualizar", r"corriger", r"mettre [àa] jour", r"korrigier",
                   r"aktualisier", r"[äa]ndern", r"correggere", r"aggiornare", "変更", "訂正", "변경", "수정", "更正", "更改", "修改"],
    "opt-out": [r"\bunsubscribe\b", r"\bopt[- ]?out\b", r"\bstop (?:sending|the|all)? ?(?:promotional|marketing|sms|newsletter)",
                r"\bno more (?:emails|newsletters|promotions)\b", r"darme de baja", r"descadastr", r"d[ée]sabonner",
                r"abmelden", r"disiscriv"],
    "login": [r"\blog ?in\b", r"\bsign ?in\b", r"\bpassword\b", r"\blocked out\b", r"\bcredentials?\b", r"\breset\b",
              r"contrase[ñn]a", r"senha", r"mot de passe", r"passwort", r"ログイン", "로그인", "密码", "密碼"],
    "billing": [r"\binvoices?\b", r"\breceipts?\b", r"\bbilling\b", r"factura", r"fatura", r"facture", r"rechnung", r"fattura",
                "請求書", "영수증", "发票", "發票"],
}

# instruction-like segments inside a customer request (cut out before classification)
INJECTION_RE = re.compile(
    r"(?:^|(?<=[\s.,;:!?\]>]))(?:"
    r"</?\s*request_text\s*>|"
    r"(?:system|assistant|developer|user|instructions?)\s*(?:prompt|message)?\s*[:>\]]|"
    r"\[\s*(?:system|inst|assistant)\s*\]|<\|?\s*(?:system|im_start|im_end)\s*\|?>|"
    r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|your)\s+"
    r"(?:instructions?|rules?|prompts?|messages?)|"
    r"(?:you\s+are\s+now|new\s+instructions?|from\s+now\s+on)\b|"
    r"(?:classify|label|mark|treat|answer|respond|reply|output|return)\s+(?:this\s+|it\s+|the\s+request\s+)?"
    r"(?:(?:as|with)\s*)?[:=]?\s*[\"']?(?:not_)?deletion\b|"
    r"[\"']?intent[\"']?\s*[:=]\s*[\"']?(?:not_)?deletion|"
    r"ignora(?:r)?\s+(?:las|todas las|as|todas as)\s+instruc|ignorez\s+(?:les|toutes les)\s+instructions|"
    r"ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen\s+)?anweisungen|ignora\s+(?:le|tutte le)\s+istruzioni|"
    r"指示を無視|이전 지시를 무시|忽略(?:之前|以上|所有)?的?(?:指令|指示)"
    r")[^.!?\n。！？]*[.!?。！？]?",
    re.I,
)


def sanitize(text):
    """(cleaned text, list of removed instruction-like segments)."""
    found = [m.group(0).strip() for m in INJECTION_RE.finditer(text) if m.group(0).strip()]
    cleaned = INJECTION_RE.sub(" ", text)
    return re.sub(r"\s+", " ", cleaned).strip(), found


def _first(patterns, t):
    return next((p for p in patterns if re.search(p, t)), None)


def rule_intent(text):
    """(label, reason) from the rule layer; ``text`` should already be sanitised."""
    t = (text or "").lower()
    keep = _first(KEEP_CUES, t)
    if keep:
        return "NOT_DELETION", f"keep cue: {keep}"
    delete = _first(DELETE_CUES, t)
    opt_out = _first(OPT_OUT_SCOPE, t)
    if delete and not opt_out:
        return "DELETION", f"deletion cue: {delete}"
    if opt_out:
        return "NOT_DELETION", f"opt-out scope: {opt_out}"
    for category, cues in CATEGORY_CUES.items():
        hit = _first(cues, t)
        if hit:
            return "NOT_DELETION", f"{category} cue: {hit}"
    return "NOT_DELETION", "no deletion cue"


def _load_cache():
    try:
        with open(CACHE, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    # keep only well-formed entries (a tampered cache must not inject labels)
    return {k: v for k, v in data.items() if isinstance(v, dict) and v.get("intent") in ("DELETION", "NOT_DELETION")}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    tmp = CACHE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=1, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, CACHE)


def _prompt():
    with open(PROMPT, encoding="utf-8") as fh:
        text = fh.read()
    system = text.split("## System", 1)[1].split("## User", 1)[0].strip()
    user = text.split("## User", 1)[1].strip()
    return system, user


def anthropic_errors():
    """SDK error classes (empty tuple when the SDK is not installed)."""
    try:
        import anthropic
    except ImportError:
        return ()
    names = ("APIStatusError", "APIConnectionError", "AuthenticationError")
    return tuple(getattr(anthropic, n) for n in names if isinstance(getattr(anthropic, n, None), type))


ANSWER_SCHEMA = {
    "type": "object",
    "properties": {"intent": {"type": "string", "enum": ["DELETION", "NOT_DELETION"]},
                   "reason": {"type": "string"}},
    "required": ["intent", "reason"],
    "additionalProperties": False,
}


def _llm_intent(text, client=None):
    client = client or keys.client()
    system, user = _prompt()
    # the closing delimiter cannot be smuggled in to break out of the data block
    safe = text.replace("</request_text>", "</request_text_>")[:4000]
    resp = client.messages.create(model=MODEL, max_tokens=MAX_TOKENS, system=system,
                                  output_config={"effort": "low",
                                                 "format": {"type": "json_schema", "schema": ANSWER_SCHEMA}},
                                  messages=[{"role": "user", "content": user.replace("{request_text}", safe)}])
    ledger.record("intent", MODEL, resp.usage)
    if resp.stop_reason == "refusal":
        raise ValueError("model refused")
    if resp.stop_reason == "max_tokens":
        raise ValueError("answer truncated at max_tokens")
    out = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        raise ValueError("no JSON in model answer")
    data = json.loads(m.group(0))
    if not isinstance(data, dict) or data.get("intent") not in ("DELETION", "NOT_DELETION"):
        raise ValueError("unexpected answer schema")
    return data["intent"], str(data.get("reason", ""))[:200]


class IntentClassifier:
    def __init__(self, use_llm=None):
        self.cache = _load_cache()
        self.use_llm = bool(keys.api_key()) if use_llm is None else use_llm
        self.stats = {"llm_calls": 0, "cache_hits": 0, "rule_only": 0, "llm_errors": {}, "injection_flags": 0,
                      "disagreements": []}
        self.memo = {}  # text -> result within this run (stats count each distinct text once)

    def classify(self, text):
        """Return (is_deletion, source, reason)."""
        text = text or ""
        if text in self.memo:
            return self.memo[text]
        cleaned, injected = sanitize(text)
        if not cleaned.strip():
            self.memo[text] = (False, "rules", "empty request text" + (" (only injected instructions)" if injected else ""))
            return self.memo[text]
        if injected:
            self.stats["injection_flags"] += 1
        key = hashlib.sha256(text.encode()).hexdigest()
        rule_label, rule_reason = rule_intent(cleaned)
        if key in self.cache:
            self.stats["cache_hits"] += 1
            hit = self.cache[key]
            label, src, reason = hit["intent"], f"cache:{hit.get('source', 'llm')}", hit["reason"]
        elif self.use_llm:
            try:
                label, reason = _llm_intent(cleaned)
                src = f"llm:{MODEL}"
                self.stats["llm_calls"] += 1
                self.cache[key] = {"intent": label, "reason": reason, "source": src}  # no raw text stored
                _save_cache(self.cache)
            except (anthropic_errors() + (ValueError, KeyError, AttributeError, TypeError)) as exc:
                # API / network errors, refusals, truncated or unparseable answers fall back to the rules;
                # main.py prints the error counts so a broken model path cannot pass unnoticed
                name = type(exc).__name__
                self.stats["llm_errors"][name] = self.stats["llm_errors"].get(name, 0) + 1
                label, src, reason = rule_label, "rules(fallback)", f"{rule_reason}; llm error {name}: {exc}"[:300]
                self.stats["rule_only"] += 1
        else:
            label, src, reason = rule_label, "rules", rule_reason
            self.stats["rule_only"] += 1
        if label != rule_label:
            self.stats["disagreements"].append((key[:12], label, rule_label))
            if injected:
                # the text tried to steer the classifier: only the layer it cannot steer decides
                label, src, reason = rule_label, src + "+injection-guard", f"{rule_reason}; injected: {injected[0][:60]}"
            elif label == "DELETION" and rule_reason.startswith("keep cue"):
                # destructive action needs both layers: an explicit "keep / do not delete"
                # cue overrides a model DELETION
                label, src, reason = "NOT_DELETION", src + "+rules-veto", rule_reason
        self.memo[text] = (label == "DELETION", src, reason)
        return self.memo[text]
