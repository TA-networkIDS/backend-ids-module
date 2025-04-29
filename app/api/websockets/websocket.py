from fastapi import APIRouter, WebSocket
from typing import List, Dict, Any, Optional
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
BROADCAST_INTERVAL = 1


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.packet_count = 0
        self.message_buffer: List[Dict[str, Any]] = []
        self.broadcast_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self.low_sev_count = 0
        self.med_sev_count = 0
        self.high_sev_count = 0
        self.in_size = 0
        self.out_size = 0
        self.ip = "172.10.16.238"
        self.protocol_distribution: Dict[str, int] = {}
        self.service_distribution: Dict[str, int] = {}
        self.packet_data: List[Dict[str, Any]] = []
        self.alert_data: List[Dict[str, Any]] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print("\n[WebSocket] New connection established")
        print(
            f"[WebSocket] Active connections: {len(self.active_connections)}")
        
        if not self.broadcast_task or self.broadcast_task.done():
            self._stop_event.clear()
            self.broadcast_task = asyncio.create_task(self._periodic_broadcast())

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print("\n[WebSocket] Connection closed")
        print(f"[WebSocket] Total packets processed: {self.packet_count}")
        print(
            f"[WebSocket] Remaining connections: {len(self.active_connections)}")
        
        if not self.active_connections and self.broadcast_task:
            self._stop_event.set()

    async def _periodic_broadcast(self):
        """Periodically broadcast buffered messages at fixed intervals"""
        while not self._stop_event.is_set():
            if self.alert_data and self.packet_data:
                # Create a copy of the buffer and clear it
                # messages_to_send = self.message_buffer.copy()
                total_low = self.low_sev_count
                total_med = self.med_sev_count
                total_high = self.high_sev_count
                protocols_counts = self.protocol_distribution.copy()
                services_counts = self.service_distribution.copy()
                inbound = self.in_size
                outbound = self.out_size
                alerts_data = self.alert_data.copy()
                packets_data = self.packet_data.copy()

                self.low_sev_count = 0
                self.med_sev_count = 0
                self.high_sev_count = 0
                self.message_buffer.clear()
                self.protocol_distribution.clear()
                self.service_distribution.clear()
                self.in_size = 0
                self.out_size = 0
                self.alert_data.clear()
                self.packet_data.clear()
                
                
                # Broadcast all messages
                for connection in self.active_connections:
                    try:
                        # Send as a list of messages or individually as needed
                        await connection.send_json({
                            "type": "batch_update",
                            "pkt_in": inbound,
                            "pkt_out": outbound,
                            "low_count": total_low,
                            "med_count": total_med,
                            "high_count": total_high,
                            "protocols_count": protocols_counts,
                            "services_count": services_counts,
                            "alerts_data": alerts_data,
                            "packets_data": packets_data
                        })
                    except Exception as e:
                        print(f"[WebSocket] Error broadcasting to connection: {e}")
            
            await asyncio.sleep(BROADCAST_INTERVAL)

    async def broadcast(self, message: dict):
        """Add message to buffer to be sent in next broadcast"""
        # self.message_buffer.append(message)
        if message["predicted_class"] == "Probe" : self.low_sev_count+=1
        elif message["predicted_class"] == "Dos" : self.med_sev_count+=1
        elif message["predicted_class"] == "U2R" or message["predicted_class"] == "R2L": self.high_sev_count+=1
        else: pass

        if message["ipsrc"] == self.ip: self.in_size+=message["len"]
        elif message["ipdst"] == self.ip: self.out_size+=message["len"]
        else: pass

        self.protocol_distribution[message["protocol_type"]] = \
            self.protocol_distribution.get(message["protocol_type"], 0) + 1
        
        self.service_distribution[message["service"]] = \
            self.service_distribution.get(message["service"], 0) + 1
        
        self.packet_data.append({
            "formatted_timestamp" : message["formatted_timestamp"],
            "ipsrc": message["ipsrc"],
            "ipdst": message["ipdst"],
            "sport": message["sport"],
            "dport": message["dport"],
            "ttl": message["ttl"],
            "chksum": message["chksum"],
            "len": message["len"],
            "flag": message["flag"],
            "protocol_type": message["protocol_type"],
            "service": message["service"],
            "chksum_transport": message["chksum_transport"]
        })

        self.alert_data.append({
            "ipsrc": message["ipsrc"],
            "formatted_timestamp": message["formatted_timestamp"],
            "predicted_class": message["predicted_class"],
            "confidence": message["confidence"]
        })


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
