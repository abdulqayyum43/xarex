"""
Prospect enrichment — takes a company domain or name and returns
enriched lead data using Apollo.io (or falls back to web search).
"""
import os
import httpx
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Prospect:
    name: str
    title: str
    company: str
    email: Optional[str] = None
    linkedin_url: Optional[str] = None
    company_description: str = ""
    company_domain: str = ""
    recent_news: Optional[str] = None
    employee_count: Optional[int] = None
    industry: str = ""


def enrich_from_apollo(domain: str, title_filter: str = "CEO,CTO,VP,Director,Head") -> list[Prospect]:
    """Query Apollo.io people search API for decision-makers at a domain."""
    api_key = os.environ.get("APOLLO_API_KEY")
    if not api_key:
        return []

    try:
        resp = httpx.post(
            "https://api.apollo.io/v1/mixed_people/search",
            headers={"Content-Type": "application/json", "Cache-Control": "no-cache"},
            json={
                "api_key": api_key,
                "q_organization_domains": domain,
                "person_titles": title_filter.split(","),
                "per_page": 10,
            },
            timeout=15,
        )
        data = resp.json()
        prospects = []
        for person in data.get("people", []):
            org = person.get("organization", {})
            prospects.append(
                Prospect(
                    name=person.get("name", ""),
                    title=person.get("title", ""),
                    company=org.get("name", ""),
                    email=person.get("email"),
                    linkedin_url=person.get("linkedin_url"),
                    company_description=org.get("short_description", ""),
                    company_domain=domain,
                    employee_count=org.get("estimated_num_employees"),
                    industry=org.get("industry", ""),
                )
            )
        return prospects
    except Exception:
        return []


def build_prospect_from_dict(data: dict) -> Prospect:
    return Prospect(
        name=data.get("name", ""),
        title=data.get("title", ""),
        company=data.get("company", ""),
        email=data.get("email"),
        linkedin_url=data.get("linkedin_url"),
        company_description=data.get("company_description", ""),
        company_domain=data.get("company_domain", ""),
        recent_news=data.get("recent_news"),
        employee_count=data.get("employee_count"),
        industry=data.get("industry", ""),
    )
