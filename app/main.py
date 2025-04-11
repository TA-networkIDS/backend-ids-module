import uvicorn
from fastapi import FastAPI
from app.api.routes import routes
from app.api.websockets import websocket

app = FastAPI()

app.include_router(routes.router)
app.include_router(websocket.router)

@app.get("/")
async def root():
    return {"message": "IDS Backend is running."}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
