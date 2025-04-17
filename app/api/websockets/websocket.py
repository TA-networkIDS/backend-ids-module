from fastapi import APIRouter, WebSocket
from typing import List, Dict, Any
import json
import asyncio
from pydantic import BaseModel
import pandas as pd
import numpy as np
import joblib
import os
import tensorflow as tf
from app.models.model import predict as model_predict
from app.preprocessing.payload import create_broadcast_payload
router = APIRouter()

# # Constants
# BATCH_SIZE = 1  # Number of packets to process in a batch
# PROCESS_INTERVAL = 0.001  # Process data every 2 seconds


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.packet_count = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print("\n[WebSocket] New connection established")
        print(
            f"[WebSocket] Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print("\n[WebSocket] Connection closed")
        print(f"[WebSocket] Total packets processed: {self.packet_count}")
        print(
            f"[WebSocket] Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        for connection in self.active_connections:
            await connection.send_json(message)

    async def process_packet(self, data: Dict[str, Any]):
        """Process a single packet and run inference"""
        try:
            # Keep original data for broadcast
            original_data = data.copy()

            # Remove fields not needed for inference
            inference_data = data.copy()
            inference_data.pop('timestamp', None)
            inference_data.pop('rawBytes', None)

            # Run inference on single packet
            # Pass as list since model expects array
            result = model_predict([inference_data])[0]

            # Create and broadcast payload
            payload = create_broadcast_payload(original_data, result)
            # await self.broadcast({
            #     "type": "prediction_result",
            #     "data": payload
            # })
            print(payload)
            await self.broadcast(payload)

            # Log alert if detected
            if result["predicted_class"] != "normal":
                print(
                    f"\n[ALERT] Potential intrusion detected at timestamp {original_data['timestamp']}")
                print(f"Details: {result}")

            self.packet_count += 1

        except Exception as e:
            error_msg = f"Error processing packet: {str(e)}"
            # print(f"\n[WebSocket] {error_msg}")
            # await self.broadcast({"type": "error", "message": error_msg})


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Process each packet individually
            await manager.process_packet(data)

    except Exception as e:
        print(f"\n[WebSocket] Error: {e}")
    finally:
        manager.disconnect(websocket)
