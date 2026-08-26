from fastapi import APIRouter
from app.api.v1 import email, investigation, reports, cases

v1_router = APIRouter()
v1_router.include_router(email.router, prefix="/emails", tags=["Emails"])
v1_router.include_router(investigation.router, prefix="/investigations", tags=["Investigations"])
v1_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
v1_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
