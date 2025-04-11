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

router = APIRouter()

# Constants
BATCH_SIZE = 1  # Number of packets to process in a batch
PROCESS_INTERVAL = 0.001  # Process data every 2 seconds

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.packet_count = 0
        self.packet_buffer = []
        self.last_process_time = 0
        
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

    # async def broadcast(self, message: dict):
    #     """Send message to all connected clients"""
    #     for connection in self.active_connections:
    #         await connection.send_json(message)
    
    async def buffer_and_process(self, data: Dict[str, Any]):
        """Buffer incoming data and process in batches"""
        self.packet_count += 1
        self.packet_buffer.append(data)
        
        # Process when buffer reaches batch size or when interval elapsed
        current_time = asyncio.get_event_loop().time()
        should_process = (
            len(self.packet_buffer) >= BATCH_SIZE or 
            (current_time - self.last_process_time) >= PROCESS_INTERVAL and self.packet_buffer
        )
        
        if should_process:
            await self.process_batch()
            self.last_process_time = current_time

    async def process_batch(self):
        """Process a batch of packets and run inference"""
        if not self.packet_buffer:
            return
        
        try:
            # Prepare data for inference
            batch_data = {"data": self.packet_buffer.copy()}
            
            # Run inference
            results = model_predict(batch_data["data"])

            print(results)
            
            # Send results to all connected clients
            # message = {
            #     "type": "prediction_results",
            #     "data": results,
            #     "packet_count": len(results)
            # }
            # await self.broadcast(message)
            
            # Log results (optional)
            alerts = [r for r in results if r["predicted_class"] != "normal"]
            if alerts:
                print(f"\n[ALERT] Detected {len(alerts)} potential intrusions")
                
            # Clear the buffer
            self.packet_buffer = []
            
        except Exception as e:
            error_msg = f"Error processing batch: {str(e)}"
            print(f"\n[WebSocket] {error_msg}")
            await self.broadcast({"type": "error", "message": error_msg})
            # Clear buffer on error to avoid getting stuck
            self.packet_buffer = []
        

manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Process network packet data
            await manager.buffer_and_process(data)
            
    except Exception as e:
        print(f"\n[WebSocket] Error: {e}")
    finally:
        manager.disconnect(websocket)