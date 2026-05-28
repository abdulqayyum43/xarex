"""
Customer support agent — uses Claude + RAG context to answer tickets.
Returns a response and a confidence score (0.0–1.0).
Escalates to human when confidence < threshold.
"""
from dataclasses import dataclass
from sqlalchemy.orm import Session
from core.claude_client import run_agent
from agents.support.ingestion import retrieve_context


SYSTEM_PROMPT = """You are a friendly, knowledgeable customer support agent.
You answer questions based ONLY on the provided knowledge base context.
If the answer is not in the context, say so clearly and offer to escalate.

Always:
- Be concise and direct
- Use the customer's name if provided
- End with "Is there anything else I can help you with?"

Respond in JSON with this exact structure:
{
  "answer": "<your response to the customer>",
  "confidence": <float 0.0-1.0>,
  "should_escalate": <boolean>,
  "escalation_reason": "<reason if escalating, else null>"
}"""


@dataclass
class SupportResponse:
    answer: str
    confidence: float
    should_escalate: bool
    escalation_reason: str | None
    tokens_used: int


def answer_ticket(
    db: Session,
    org_id: str,
    ticket_text: str,
    customer_name: str = None,
    escalate_threshold: float = 0.6,
) -> SupportResponse:
    context = retrieve_context(db, org_id, ticket_text)

    user_message = f"""Customer{f' ({customer_name})' if customer_name else ''}: {ticket_text}

Knowledge base context:
{context if context else 'No relevant context found.'}"""

    response = run_agent(
        SYSTEM_PROMPT,
        [{"role": "user", "content": user_message}],
        model="claude-opus-4-7",
    )

    tokens = response.usage.input_tokens + response.usage.output_tokens
    text = next((b.text for b in response.content if b.type == "text"), "{}")

    import json
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {
            "answer": text,
            "confidence": 0.5,
            "should_escalate": True,
            "escalation_reason": "Could not parse structured response",
        }

    confidence = float(parsed.get("confidence", 0.5))
    should_escalate = parsed.get("should_escalate", False) or confidence < escalate_threshold

    return SupportResponse(
        answer=parsed.get("answer", ""),
        confidence=confidence,
        should_escalate=should_escalate,
        escalation_reason=parsed.get("escalation_reason"),
        tokens_used=tokens,
    )
