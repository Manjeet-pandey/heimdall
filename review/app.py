"""Review page: live feed, blocked moves with reasons, budget per agent, who answered."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}
