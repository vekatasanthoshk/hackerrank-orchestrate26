"""Deletion-vs-not intent classifier: Claude Haiku + disk cache + multilingual rule fallback.

* With ``ANTHROPIC_API_KEY`` set, each distinct request text is classified once by
  ``claude-haiku-5-5`` (prompt: prompts/intent_classification.md, effort low) and
  cached in cache/intent_cache.json; usage is written to the run ledger.
* Without a key (or on an API error) the deterministic rule classifier below is used.
  The rule classifier is also reported next to the LLM label so disagreements are
  visible during evaluation.
"""
import hashlib
import json
import os
import re

import ledger

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache", "intent_cache.json")
PROMPT = os.path.join(HERE, "prompts", "intent_classification.md")
MODEL = os.environ.get("INTENT_MODEL", "claude-haiku-5-5")

DELETE_CUES = [
    r"\bdelet", r"\berase", r"\berasure", r"\bremov", r"\bclos(?:e|ed|ing) (?:my|this|the) account",
    r"\baccount (?:is|was) (?:gone|closed)", r"\bprofile is gone", r"\bclean .* out of",
    r"\bdisconnect", r"\bforget me\b", r"\bwipe\b",
    r"supprim", r"suppression", r"effac",            # fr
    r"elimin", r"borr", r"cancelar (?:mi|la) cuenta",  # es
    r"exclu", r"apag",                                  # pt
    r"lösch", r"loesch", r"entfern",                    # de
    r"cancell", r"cancella", r"rimuov",                 # it
    "削除", "退会", "삭제", "탈퇴", "删除", "注销",        # ja / ko / zh
]
NOT_DELETE_CUES = [
    r"\bkeep (?:the|my) (?:account|profile)", r"\bleave (?:the|my) (?:account|profile)",
    r"\bleave the account active", r"\bdo not (?:close|delete)", r"\bdon't (?:close|delete)",
    r"\bwithout (?:removing|deleting)", r"\bcontinue using", r"\bstill want",
    r"\bmarketing lists? only", r"\bunsubscribe", r"\bstop (?:the )?(?:promotional|marketing)",
    r"\b(?:send me|need|get|receive) a copy of", r"\bdownload my", r"\bportable format", r"\bwhat (?:personal )?(?:information|data) you hold",
    r"\bcorrect (?:it|my)", r"\bmisspel", r"\bchange the email", r"\bupdate my", r"\bout of date",
    r"\breset(?:ting)? the login", r"\breset my password", r"\binvoices?\b.*\brecords\b",
    # es / pt / fr / de / it
    r"copia de mis datos", r"descargar", r"no (?:cierren|eliminen|borren)", r"mantener (?:mi|la) cuenta",
    r"solo de (?:las )?listas", r"corregir", r"actualizar",
    r"c[oó]pia dos meus dados", r"baixar", r"manter (?:minha|a) conta", r"n[aã]o (?:excluam|apaguem|fechem)",
    r"copie de mes donn[ée]es", r"t[ée]l[ée]charger", r"conserver mon compte", r"garder mon compte",
    r"ne (?:pas )?(?:supprimer|fermer)", r"uniquement des listes", r"listes? marketing", r"corriger",
    r"kopie meiner daten", r"herunterladen", r"konto behalten", r"nicht (?:l[öo]schen|schlie[ßs]en)",
    r"copia dei miei dati", r"non (?:chiudere|cancellare|eliminare)",
    # ja / ko / zh
    "ダウンロード", "コピー", "削除しないで", "変更", "訂正", "配信停止",
    "다운로드", "사본", "삭제하지", "변경", "수정", "수신 거부",
    "下载", "副本", "不要删除", "更正", "退订",
]


def rule_intent(text):
    t = text.lower()
    neg = [p for p in NOT_DELETE_CUES if re.search(p, t)]
    pos = [p for p in DELETE_CUES if re.search(p, t)]
    if neg:
        return "NOT_DELETION", f"non-deletion cue: {neg[0]}"
    if pos:
        return "DELETION", f"deletion cue: {pos[0]}"
    return "NOT_DELETION", "no deletion cue"


def _load_cache():
    if os.path.exists(CACHE):
        return json.load(open(CACHE, encoding="utf-8"))
    return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    json.dump(cache, open(CACHE, "w", encoding="utf-8"), indent=1, ensure_ascii=False, sort_keys=True)


def _prompt():
    text = open(PROMPT, encoding="utf-8").read()
    system = text.split("## System", 1)[1].split("## User", 1)[0].strip()
    user = text.split("## User", 1)[1].strip()
    return system, user


def anthropic_errors():
    """SDK error classes (empty tuple when the SDK is not installed)."""
    try:
        import anthropic

        return (anthropic.APIStatusError, anthropic.APIConnectionError, anthropic.AuthenticationError)
    except ImportError:
        return ()


def _llm_intent(text):
    import anthropic

    client = anthropic.Anthropic()
    system, user = _prompt()
    resp = client.messages.create(model=MODEL, max_tokens=1024, system=system,
                                  output_config={"effort": "low"},
                                  messages=[{"role": "user", "content": user.replace("{request_text}", text)}])
    ledger.record("intent", MODEL, resp.usage)
    if resp.stop_reason == "refusal":
        raise ValueError("model refused")
    out = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        raise ValueError("no JSON in model answer")
    data = json.loads(m.group(0))
    label = "DELETION" if data.get("intent") == "DELETION" else "NOT_DELETION"
    return label, data.get("reason", "")


class IntentClassifier:
    def __init__(self, use_llm=None):
        self.cache = _load_cache()
        self.use_llm = bool(os.environ.get("ANTHROPIC_API_KEY")) if use_llm is None else use_llm
        self.stats = {"llm_calls": 0, "cache_hits": 0, "rule_only": 0, "disagreements": []}
        self.memo = {}  # text -> result within this run (stats count each distinct text once)

    def classify(self, text):
        """Return (is_deletion, source, reason)."""
        if text in self.memo:
            return self.memo[text]
        key = hashlib.sha256(text.encode()).hexdigest()
        rule_label, rule_reason = rule_intent(text)
        if key in self.cache:
            self.stats["cache_hits"] += 1
            hit = self.cache[key]
            label, src, reason = hit["intent"], f"cache:{hit.get('source', 'llm')}", hit["reason"]
        elif self.use_llm:
            try:
                label, reason = _llm_intent(text)
                src = f"llm:{MODEL}"
                self.stats["llm_calls"] += 1
                self.cache[key] = {"intent": label, "reason": reason, "source": src, "text": text[:160]}
                _save_cache(self.cache)
            except (anthropic_errors() + (ValueError, KeyError, AttributeError)) as exc:
                # API / network errors, refusals and unparseable answers fall back to the rules
                label, src, reason = rule_label, "rules(fallback)", f"{rule_reason}; llm error {type(exc).__name__}"
                self.stats["rule_only"] += 1
        else:
            label, src, reason = rule_label, "rules", rule_reason
            self.stats["rule_only"] += 1
        if label != rule_label:
            self.stats["disagreements"].append((text[:80], label, rule_label))
        self.memo[text] = (label == "DELETION", src, reason)
        return self.memo[text]
