from fastapi import APIRouter
from app.api.v1 import email, investigation, reports, cases, users, evidence_api, threat_intel_api

v1_router = APIRouter()
v1_router.include_router(email.router, prefix="/emails", tags=["Emails"])
v1_router.include_router(investigation.router, prefix="/investigations", tags=["Investigations"])
v1_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
v1_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
v1_router.include_router(users.router, prefix="/users", tags=["Users"])
v1_router.include_router(evidence_api.router, prefix="/evidence", tags=["Evidence"])
v1_router.include_router(threat_intel_api.router, prefix="/threat-intel", tags=["Threat Intelligence"])
