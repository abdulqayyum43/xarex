"""
Knowledge base ingestion — chunks and stores docs for the support agent's RAG pipeline.
Supports plain text, PDFs (via pdfminer), and URLs (via httpx).
"""
import re
import uuid
from typing import Optional
from sqlalchemy.orm import Session
from core.database import KnowledgeBase


def chunk_text(text: str, chunk_size: int = 1500, overlap: int = 200) -> list[str]:
    """Split text into overlapping chunks for better retrieval."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i : i + chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


def ingest_text(db: Session, org_id: str, name: str, content: str, source_url: str = None):
    chunks = chunk_text(content)
    for i, chunk in enumerate(chunks):
        kb = KnowledgeBase(
            id=uuid.uuid4(),
            org_id=org_id,
            name=f"{name} (part {i + 1})",
            content=chunk,
            source_url=source_url,
        )
        db.add(kb)
    db.commit()
    return len(chunks)


async def ingest_url(db: Session, org_id: str, url: str) -> int:
    import httpx
    from html.parser import HTMLParser

    class TextExtractor(HTMLParser):
        def __init__(self):
            super().__init__()
            self.texts = []
            self._skip = False

        def handle_starttag(self, tag, attrs):
            if tag in ("script", "style", "nav", "footer"):
                self._skip = True

        def handle_endtag(self, tag):
            if tag in ("script", "style", "nav", "footer"):
                self._skip = False

        def handle_data(self, data):
            if not self._skip:
                stripped = data.strip()
                if stripped:
                    self.texts.append(stripped)

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=15, follow_redirects=True)
        resp.raise_for_status()

    parser = TextExtractor()
    parser.feed(resp.text)
    text = " ".join(parser.texts)
    text = re.sub(r"\s+", " ", text).strip()
    return ingest_text(db, org_id, url, text, source_url=url)


def retrieve_context(db: Session, org_id: str, query: str, top_k: int = 5) -> str:
    """Simple keyword-based retrieval (replace with pgvector for production)."""
    query_words = set(query.lower().split())
    chunks = db.query(KnowledgeBase).filter(KnowledgeBase.org_id == org_id).all()

    scored = []
    for chunk in chunks:
        if not chunk.content:
            continue
        content_words = set(chunk.content.lower().split())
        score = len(query_words & content_words)
        scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:top_k]
    return "\n\n---\n\n".join(c.content for _, c in top if c.content)
