from groq import AsyncGroq
from app.core.config import settings
_client = None

async def complete(system: str, user: str, fallback: str) -> str:
    global _client
    if not settings.groq_api_key:
        return fallback
    try:
        if _client is None:
            _client = AsyncGroq(api_key=settings.groq_api_key, timeout=settings.groq_timeout_seconds, max_retries=1)
        result = await _client.chat.completions.create(
            model=settings.groq_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.2, max_tokens=300,
        )
        return (result.choices[0].message.content or fallback).strip()
    except Exception:
        return fallback
