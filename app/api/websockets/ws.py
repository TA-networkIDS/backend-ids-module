from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List
import json
import logging

router = APIRouter()
logger = logging.getLogger("websocket")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """
        Connect a new WebSocket connection
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket connection. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """
        Disconnect a WebSocket connection
        """
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        """
        Broadcast a message to all connections
        """
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for IDS alerts and updates
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open, but don't expect client to send messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

manager = ConnectionManager()
