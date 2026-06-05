"""Privacy Check API — IP info, VPN/proxy detection, DNS resolver identification."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import get_org
from models.database import get_db
from models.tables import Org
from services.privacy_check import identify_dns_resolvers, lookup_ip

router = APIRouter(prefix="/privacy", tags=["privacy"])


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For header."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


@router.get("/ip")
async def check_my_ip(
    request: Request,
    org: Org = Depends(get_org),
):
    """Return full IP intelligence for the caller's IP address."""
    ip = _get_client_ip(request)
    result = await lookup_ip(ip)
    return result


@router.get("/ip/{ip_address}")
async def check_specific_ip(
    ip_address: str,
    org: Org = Depends(get_org),
):
    """Check a specific IP address (useful when testing behind proxies)."""
    return await lookup_ip(ip_address)


@router.get("/dns")
async def check_dns_resolvers(
    org: Org = Depends(get_org),
    db: AsyncSession = Depends(get_db),
):
    """Identify and assess the DNS resolvers this server is using."""
    return await identify_dns_resolvers()


@router.get("/full")
async def full_privacy_check(
    request: Request,
    org: Org = Depends(get_org),
):
    """Run all server-side privacy checks in parallel and return combined result."""
    import asyncio
    ip = _get_client_ip(request)
    ip_task  = asyncio.create_task(lookup_ip(ip))
    dns_task = asyncio.create_task(identify_dns_resolvers())
    ip_result, dns_result = await asyncio.gather(ip_task, dns_task, return_exceptions=True)

    if isinstance(ip_result, Exception):
        ip_result = {"error": str(ip_result)}
    if isinstance(dns_result, Exception):
        dns_result = {"error": str(dns_result)}

    return {
        "ip":  ip_result,
        "dns": dns_result,
    }
