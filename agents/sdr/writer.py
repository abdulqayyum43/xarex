"""
SDR Agent — generates personalized outreach emails and LinkedIn messages
using Claude, based on prospect data.
"""
import json
from dataclasses import dataclass
from core.claude_client import run_agent


SYSTEM_PROMPT = """You are an elite B2B sales copywriter.
You write highly personalized cold outreach that gets replies.

Rules:
- First line must reference something specific about the prospect (recent news, job title, company initiative)
- Value proposition in one sentence — focus on the outcome, not the product
- No more than 3 sentences in the body
- Call to action: one specific question, never "let me know if you're interested"
- Subject line: under 7 words, curiosity-driven, no clickbait

Respond in JSON:
{
  "subject": "<email subject>",
  "email_body": "<full email text>",
  "linkedin_message": "<LinkedIn connection request note, max 200 chars>",
  "follow_up_1": "<day-3 follow-up email>",
  "follow_up_2": "<day-7 follow-up email>"
}"""


@dataclass
class OutreachSequence:
    subject: str
    email_body: str
    linkedin_message: str
    follow_up_1: str
    follow_up_2: str
    tokens_used: int


def generate_outreach(
    prospect_name: str,
    prospect_title: str,
    company_name: str,
    company_description: str,
    your_product: str,
    your_value_prop: str,
    recent_news: str = None,
    sender_name: str = "Alex",
) -> OutreachSequence:
    prompt = f"""Write a cold outreach sequence for this prospect:

Prospect: {prospect_name}, {prospect_title} at {company_name}
Company: {company_description}
{f'Recent news: {recent_news}' if recent_news else ''}

Your product: {your_product}
Value proposition: {your_value_prop}
Sender name: {sender_name}"""

    response = run_agent(SYSTEM_PROMPT, [{"role": "user", "content": prompt}])
    tokens = response.usage.input_tokens + response.usage.output_tokens
    text = next((b.text for b in response.content if b.type == "text"), "{}")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {"subject": "Quick question", "email_body": text, "linkedin_message": "", "follow_up_1": "", "follow_up_2": ""}

    return OutreachSequence(
        subject=parsed.get("subject", ""),
        email_body=parsed.get("email_body", ""),
        linkedin_message=parsed.get("linkedin_message", ""),
        follow_up_1=parsed.get("follow_up_1", ""),
        follow_up_2=parsed.get("follow_up_2", ""),
        tokens_used=tokens,
    )
