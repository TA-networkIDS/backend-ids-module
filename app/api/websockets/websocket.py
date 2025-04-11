from fastapi import APIRouter, WebSocket
from typing import List
import json

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.packet_count = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print("\n[WebSocket] New connection established")
        print(f"[WebSocket] Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print("\n[WebSocket] Connection closed")
        print(f"[WebSocket] Total packets processed: {self.packet_count}")
        print(f"[WebSocket] Remaining connections: {len(self.active_connections)}")

manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            manager.packet_count += 1
            print(data)
            
            
    except Exception as e:
        print(f"\n[WebSocket] Error: {e}")
    finally:
        manager.disconnect(websocket)
