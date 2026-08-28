from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from app.services.ingestion.parser import EmailParser
from app.contracts.email import ParsedEmail

router = APIRouter()
parser = EmailParser()

@router.post("/analyze", response_model=ParsedEmail)
async def analyze_email(file: UploadFile = File(...)):
    """
    Ingest and parse a raw .eml file.
    Returns the structured EmailArtifact JSON.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename not provided")
        
    try:
        raw_bytes = await file.read()
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Empty file")
            
        # CPU-bound parsing directly inside the async view function.
        parsed_email = parser.parse(raw_bytes)
        
        # We need to return this using the response model
        return parsed_email
        
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse email: {str(e)}")
