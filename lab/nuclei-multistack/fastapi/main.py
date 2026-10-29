import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

vulnerable = os.getenv("LAB_MODE", "secure") == "vulnerable"
app = FastAPI(
    title="Nuclei FastAPI Lab",
    docs_url="/docs" if vulnerable else None,
    redoc_url="/redoc" if vulnerable else None,
    openapi_url="/openapi.json" if vulnerable else None,
)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "mode": "vulnerable" if vulnerable else "secure"}


if vulnerable:
    @app.get("/.env", response_class=PlainTextResponse)
    def exposed_environment():
        return "SECRET_KEY=lab-only-fastapi-secret\nDATABASE_URL=postgres://lab:lab@localhost/lab\n"
