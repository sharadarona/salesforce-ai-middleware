"""
AI Middleware — FastAPI
========================
Receives Case data from Salesforce Apex Queueable,
applies input guardrails, security checks, prompt building,
calls OpenAI, validates output, and returns structured summary.

Architecture:
  Salesforce Apex  →  POST /summarise-case
                          │
                    ┌─────┼──────────────────┐
                    │     │                  │
              Input      Security         Prompt
           Guardrails     Layer           Builder
                    │     │                  │
                    └─────┴──────────────────┘
                                │
                           OpenAI LLM
                                │
                    Output Validation + Safety
                                │
                         JSON Response
                                │
                    Salesforce updates Case
"""

import os
import re
import time
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from openai import OpenAI, OpenAIError
from dotenv import load_dotenv

# ─── Load environment ────────────────────────────────────────────────────────
load_dotenv()

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ai_middleware")

# ─── Config from environment ─────────────────────────────────────────────────
OPENAI_API_KEY      = os.getenv("OPENAI_API_KEY", "")
MIDDLEWARE_API_KEY  = os.getenv("MIDDLEWARE_API_KEY", "change-this-secret-key")
OPENAI_MODEL        = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_TOKENS          = int(os.getenv("MAX_TOKENS", "500"))
TEMPERATURE         = float(os.getenv("TEMPERATURE", "0.1"))   # low = consistent/deterministic
ALLOWED_ORIGINS     = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ─── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="Salesforce AI Case Summary Middleware",
    description="Secure middleware between Salesforce and OpenAI for AI-powered case summarisation.",
    version="1.0.0",
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─── OpenAI Client ───────────────────────────────────────────────────────────
client = OpenAI(api_key=OPENAI_API_KEY)

# ════════════════════════════════════════════════════════════════════════════
#  MODELS
# ════════════════════════════════════════════════════════════════════════════

class CaseSummaryRequest(BaseModel):
    """Payload received from Salesforce Apex Queueable."""
    case_id      : str  = Field(..., min_length=15, max_length=18, description="Salesforce Case ID")
    subject      : str  = Field(..., max_length=255)
    description  : str  = Field(default="", max_length=4000)
    status       : Optional[str] = Field(default="New",    max_length=50)
    priority     : Optional[str] = Field(default="Medium", max_length=50)
    case_type    : Optional[str] = Field(default="",       max_length=100)
    origin       : Optional[str] = Field(default="",       max_length=50)
    account_name : Optional[str] = Field(default="",       max_length=255)
    contact_name : Optional[str] = Field(default="",       max_length=255)

    @field_validator("case_id")
    @classmethod
    def validate_sf_id(cls, v: str) -> str:
        """Salesforce IDs are 15 or 18 alphanumeric characters."""
        if not re.match(r'^[a-zA-Z0-9]{15,18}$', v):
            raise ValueError("Invalid Salesforce ID format")
        return v

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Subject cannot be empty")
        return v.strip()


class CaseSummaryResponse(BaseModel):
    """Structured response returned to Salesforce."""
    case_id        : str
    summary        : str
    model_used     : str
    safety_status  : str   # PASSED | BLOCKED
    tokens_used    : int
    latency_ms     : int
    generated_at   : str


# ════════════════════════════════════════════════════════════════════════════
#  SECURITY LAYER — API Key Authentication
# ════════════════════════════════════════════════════════════════════════════

async def verify_api_key(request: Request):
    """
    Validates the X-API-Key header sent by Salesforce Named Credential.
    Uses constant-time comparison to prevent timing attacks.
    """
    incoming_key = request.headers.get("X-API-Key", "")
    expected_key = MIDDLEWARE_API_KEY

    # Constant-time comparison using HMAC
    import hmac
    if not hmac.compare_digest(
        hashlib.sha256(incoming_key.encode()).digest(),
        hashlib.sha256(expected_key.encode()).digest()
    ):
        logger.warning(f"Unauthorized request from {request.client.host}")
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API key")
        

    return True


# ════════════════════════════════════════════════════════════════════════════
#  INPUT GUARDRAILS
# ════════════════════════════════════════════════════════════════════════════

# Patterns to detect prompt injection attempts
INJECTION_PATTERNS = [
    r"ignore\s+previous\s+instructions?",
    r"disregard\s+(all|prior|previous)",
    r"you\s+are\s+now\s+(a|an)\s+\w+",
    r"act\s+as\s+(a|an)\s+\w+",
    r"forget\s+(everything|all)",
    r"system\s*:\s*you",
    r"jailbreak",
    r"dan\s+mode",
    r"developer\s+mode",
    r"bypass\s+(safety|filter|restriction)",
    r"<script>",
    r"--[^\n]*$",                  # SQL comment injection
    r";\s*(drop|delete|insert)\s+",  # SQL injection
]

COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

# Sensitive PII patterns — redact before sending to LLM
PII_PATTERNS = {
    "credit_card"   : r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    "ssn"           : r'\b\d{3}-\d{2}-\d{4}\b',
    "email"         : r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "phone_us"      : r'(?<!\d)(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)',
    "phone_in"      : r'(?<!\d)(?:\+91[-.\s]?)?[6-9]\d{9}(?!\d)',
    "aadhaar"       : r'\b\d{4}\s\d{4}\s\d{4}\b',
    "passport"      : r'\b[A-Z]{1,2}\d{6,9}\b',
}

COMPILED_PII = {k: re.compile(v) for k, v in PII_PATTERNS.items()}


def check_injection(text: str) -> tuple[bool, str]:
    """
    Returns (is_safe, matched_pattern).
    is_safe=False means injection detected.
    """
    for pattern in COMPILED_INJECTION:
        match = pattern.search(text)
        if match:
            return False, pattern.pattern
    return True, ""


def redact_pii(text: str) -> tuple[str, list[str]]:
    """
    Replaces PII with [REDACTED-TYPE] placeholders.
    Returns (cleaned_text, list_of_redacted_types).
    """
    redacted_types = []
    for pii_type, pattern in COMPILED_PII.items():
        if pattern.search(text):
            text = pattern.sub(f"[REDACTED-{pii_type.upper()}]", text)
            redacted_types.append(pii_type)
    return text, redacted_types


def sanitize_text(text: str) -> str:
    """Remove control characters and excessive whitespace."""
    if not text:
        return ""
    # Remove null bytes and control chars (except newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    # Collapse more than 3 consecutive newlines
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    return text.strip()


def run_input_guardrails(req: CaseSummaryRequest) -> tuple[bool, str, CaseSummaryRequest]:
    """
    Runs all input guardrails. Returns:
      (is_safe, reason_if_blocked, cleaned_request)
    """
    combined_text = f"{req.subject} {req.description}"

    # 1. Injection check
    is_safe, pattern = check_injection(combined_text)
    if not is_safe:
        logger.warning(f"[GUARDRAIL] Injection detected in case {req.case_id}. Pattern: {pattern}")
        return False, f"Prompt injection detected", req

    # 2. PII redaction
    clean_subject, redacted_s = redact_pii(req.subject)
    clean_desc,    redacted_d = redact_pii(req.description or "")
    all_redacted = list(set(redacted_s + redacted_d))
    if all_redacted:
        logger.info(f"[GUARDRAIL] PII redacted for case {req.case_id}: {all_redacted}")

    # 3. Sanitize
    clean_subject = sanitize_text(clean_subject)
    clean_desc    = sanitize_text(clean_desc)
    logger.info(f"Clean Subject for case {req.case_id}: {clean_subject}")
    logger.info(f"Clean Description for case {req.case_id}: {clean_desc}")

    # 4. Minimum content check
    if len(clean_subject.strip()) < 3:
        return False, "Subject too short to generate meaningful summary", req
    
    
    # Return cleaned request
    cleaned = req.model_copy(update={
        "subject"    : clean_subject,
        "description": clean_desc
    })
    return True, "", cleaned


# ════════════════════════════════════════════════════════════════════════════
#  PROMPT BUILDER
# ════════════════════════════════════════════════════════════════════════════

def build_prompt(req: CaseSummaryRequest) -> list[dict]:
    """
    Constructs a structured OpenAI messages array.
    Uses system/user role separation for best results.
    """

    system_prompt = """You are an expert Salesforce CRM assistant specialising in customer support operations.
Your task is to generate a concise, structured summary of a customer support case.

STRICT RULES:
1. Respond ONLY with the 3 bullet points described below. No preamble, no explanation.
2. Each bullet starts with the exact label shown.
3. Be factual. Do not invent information not present in the case.
4. If a field is empty, skip it — do not guess.
5. Keep total response under 200 words.
6. Use professional English. No slang, no speculation.

OUTPUT FORMAT (exactly this structure):
• ISSUE/REQUEST: [One sentence describing the core issue the customer is facing]
• SENTIMENT: [Customer's emotional tone: Frustrated / Neutral / Urgent / Confused / Satisfied]
• ACTION: [Recommended next step for the support agent]"""

    # Build context-rich user prompt
    case_context_parts = [
        f"Subject: {req.subject}",
    ]

    if req.description and req.description.strip():
        case_context_parts.append(f"Description: {req.description}")

    if req.priority:
        case_context_parts.append(f"Priority: {req.priority}")

    if req.case_type:
        case_context_parts.append(f"Type: {req.case_type}")

    if req.origin:
        case_context_parts.append(f"Channel: {req.origin}")

    if req.account_name:
        case_context_parts.append(f"Account: {req.account_name}")

    if req.contact_name:
        case_context_parts.append(f"Contact: {req.contact_name}")

    user_prompt = "Generate a 3-bullet summary for this Salesforce support case:\n\n"
    user_prompt += "\n".join(case_context_parts)

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt}
    ]


# ════════════════════════════════════════════════════════════════════════════
#  OUTPUT VALIDATION + SAFETY FILTERS
# ════════════════════════════════════════════════════════════════════════════

# Content that should never appear in a case summary
BLOCKED_OUTPUT_PATTERNS = [
    r"<script>",
    r"ignore\s+previous",
    r"as\s+an\s+ai\s+(language\s+)?model",
    r"i\s+(cannot|can't|am\s+unable)\s+provide",
    r"i\s+am\s+not\s+able\s+to",
]
COMPILED_BLOCKED = [re.compile(p, re.IGNORECASE) for p in BLOCKED_OUTPUT_PATTERNS]

def validate_output(text: str) -> tuple[bool, str]:
    """
    Checks LLM output for:
    1. Minimum content presence (has expected bullet structure)
    2. Blocked content patterns
    3. Reasonable length
    Returns (is_valid, reason_if_invalid)
    """
    if not text or len(text.strip()) < 20:
        return False, "Output too short"

    if len(text) > 3000:
        return False, "Output suspiciously long"

    # Check for blocked patterns
    for pattern in COMPILED_BLOCKED:
        if pattern.search(text):
            return False, f"Blocked pattern in output"

    # Verify expected bullet structure is present
    has_problem   = "ISSUE/REQUEST:"   in text.upper()
    has_sentiment = "SENTIMENT:" in text.upper()
    has_action    = "ACTION:"    in text.upper()

    if not (has_problem and has_sentiment and has_action):
        logger.warning("Output missing expected bullet structure — may still be usable")
        # Don't block, just warn — LLM sometimes varies the format slightly

    return True, ""


# ════════════════════════════════════════════════════════════════════════════
#  MAIN ENDPOINT
# ════════════════════════════════════════════════════════════════════════════

@app.post(
    "/summarise-case",
    response_model=CaseSummaryResponse,
    summary="Generate AI summary for a Salesforce Case",
    description="Called by Salesforce Apex Queueable. Applies guardrails, builds prompt, calls OpenAI, validates output."
)
async def summarise_case(
    request_body: CaseSummaryRequest,
    _auth: bool = Depends(verify_api_key)
):
    start_time = time.time()
    logger.info(f"[REQUEST] Case: {request_body.case_id} | Priority: {request_body.priority}")

    # ── Step 1: Input Guardrails ──────────────────────────────────────────────
    is_safe, reason, clean_req = run_input_guardrails(request_body)
    if not is_safe:
        logger.warning(f"[BLOCKED] Case {request_body.case_id} blocked at guardrails: {reason}")
        return CaseSummaryResponse(
            case_id       = request_body.case_id,
            summary       = "",
            model_used    = OPENAI_MODEL,
            safety_status = "BLOCKED",
            tokens_used   = 0,
            latency_ms    = int((time.time() - start_time) * 1000),
            generated_at  = datetime.now(timezone.utc).isoformat()
        )

    # ── Step 2: Build Prompt ──────────────────────────────────────────────────
    messages = build_prompt(clean_req)
    logger.info(f"[PROMPT] Built prompt for case {clean_req.case_id}")

    # ── Step 3: Call OpenAI ───────────────────────────────────────────────────
    try:
        response = client.chat.completions.create(
            model       = OPENAI_MODEL,
            messages    = messages,
            max_tokens  = MAX_TOKENS,
            temperature = TEMPERATURE,
            n           = 1,
        )

        summary_text = response.choices[0].message.content.strip()
        tokens_used  = response.usage.total_tokens
        logger.info(f"[LLM] Case {clean_req.case_id} | Tokens: {tokens_used} | Model: {OPENAI_MODEL}")

    except OpenAIError as e:
        logger.error(f"[OPENAI ERROR] Case {clean_req.case_id}: {str(e)}")
        raise HTTPException(status_code=502, detail=f"LLM service error: {str(e)}")

    # ── Step 4: Output Validation + Safety ───────────────────────────────────
    is_valid, reason = validate_output(summary_text)
    if not is_valid:
        logger.warning(f"[SAFETY] Output blocked for case {clean_req.case_id}: {reason}")
        return CaseSummaryResponse(
            case_id       = clean_req.case_id,
            summary       = "",
            model_used    = OPENAI_MODEL,
            safety_status = "BLOCKED",
            tokens_used   = tokens_used,
            latency_ms    = int((time.time() - start_time) * 1000),
            generated_at  = datetime.now(timezone.utc).isoformat()
        )

    latency_ms = int((time.time() - start_time) * 1000)
    logger.info(f"[SUCCESS] Case {clean_req.case_id} | Latency: {latency_ms}ms")

    return CaseSummaryResponse(
        case_id       = clean_req.case_id,
        summary       = summary_text,
        model_used    = OPENAI_MODEL,
        safety_status = "PASSED",
        tokens_used   = tokens_used,
        latency_ms    = latency_ms,
        generated_at  = datetime.now(timezone.utc).isoformat()
    )


# ════════════════════════════════════════════════════════════════════════════
#  HEALTH + STATUS ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════

@app.get("/health", summary="Health check")
async def health():
    """Used by Render/Railway to confirm the service is alive."""
    return {
        "status"     : "healthy",
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
        "model"      : OPENAI_MODEL,
        "api_key_set": bool(OPENAI_API_KEY)
    }


@app.get("/", summary="Service info")
async def root():
    return {
        "service"    : "Salesforce AI Case Summary Middleware",
        "version"    : "1.0.0",
        "endpoints"  : ["/summarise-case", "/health", "/docs"]
    }


# ─── Dev entrypoint ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
