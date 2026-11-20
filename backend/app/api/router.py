"""Root router for the API foundation."""

from fastapi import APIRouter

from app.alerts.router import router as alerts_router
from app.api.health import router as health_router
from app.assets.router import router as assets_router
from app.auth.router import router as auth_router
from app.cloud_accounts.router import router as cloud_accounts_router
from app.compliance.router import router as compliance_router
from app.customer_scans.router import router as customer_scans_router
from app.dashboard.router import router as dashboard_router
from app.findings.router import router as findings_router
from app.identity.router import router as identity_router
from app.operations.router import router as operations_router
from app.organizations.router import router as organizations_router
from app.policies.router import router as policies_router
from app.risk.router import router as risk_router
from app.scan_jobs.router import router as scan_jobs_router
from app.scim.router import router as scim_router
from app.search.router import router as search_router
from app.teams.router import router as teams_router
from app.users.router import router as users_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(dashboard_router)
api_router.include_router(search_router)
api_router.include_router(auth_router)
api_router.include_router(identity_router)
api_router.include_router(scim_router)
api_router.include_router(organizations_router)
api_router.include_router(users_router)
api_router.include_router(teams_router)
api_router.include_router(cloud_accounts_router)
api_router.include_router(scan_jobs_router)
api_router.include_router(customer_scans_router)
api_router.include_router(assets_router)
api_router.include_router(policies_router)
api_router.include_router(findings_router)
api_router.include_router(risk_router)
api_router.include_router(compliance_router)
api_router.include_router(operations_router)
api_router.include_router(alerts_router)
