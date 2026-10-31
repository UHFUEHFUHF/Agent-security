from datetime import datetime, timezone
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from app.api.deps import get_current_user
from app.db.mongo import get_db
from app.services.document_analysis import extract_document_text, analyze_invoice, MAX_DOCUMENT_BYTES

router = APIRouter(prefix="/documents", tags=["documents"])

@router.post("/analyze-invoice")
async def analyze_invoice_upload(file: UploadFile = File(...), user=Depends(get_current_user), db=Depends(get_db)):
    data = await file.read(MAX_DOCUMENT_BYTES + 1)
    try:
        text = extract_document_text(file.filename or "upload.txt", file.content_type or "", data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = analyze_invoice(text)
    now = datetime.now(timezone.utc)
    doc = {"owner_id": user["id"], "filename": (file.filename or "upload")[:180],
           "analysis": result, "created_at": now}
    inserted = await db.document_analyses.insert_one(doc)
    await db.audit_logs.insert_one({"owner_id": user["id"], "event": "invoice_analyzed",
        "document_id": str(inserted.inserted_id), "guardian_decision": result["guardian_decision"], "created_at": now})
    return {"id": str(inserted.inserted_id), "filename": doc["filename"], **result,
            "message": "No real payment was initiated. All payment behaviour is simulated."}
