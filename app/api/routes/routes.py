# REST API for testing model and network statistics

import asyncio
import logging
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from app.models.model import predict
from app.mongodb import mongodb_client
from typing import List, Dict, Any

logger = logging.getLogger("myapp")

router = APIRouter()

class NetworkDataPayload(BaseModel):
    data: list

@router.post("/predict")
async def predict_route(data: NetworkDataPayload):
    try:
        input_data_list = data.data
        
        results = predict(input_data_list)
        
        return results
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in prediction: {error_details}")
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@router.get("/network-statistics")
async def get_network_statistics():
    """
    Retrieve current network statistics from the database
    
    Returns:
    - Packet counts
    - Protocol distribution
    - Service distribution
    - Attack type distribution
    - Top talkers, ports, and attackers
    """
    try:
        # Ensure we're using the correct event loop
        loop = asyncio.get_running_loop()
        logger.info("Getting network statistics using event loop: %s", id(loop))
        
        stats = await mongodb_client.get_network_statistics()
        if not stats:
            raise HTTPException(status_code=404, detail="No network statistics found")
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error retrieving network statistics: %s", str(e), exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve network statistics: {str(e)}"
        )

@router.post("/reset-network-statistics")
async def reset_network_statistics():
    """
    Reset all network statistics in the database
    """
    try:
        # Create an empty statistics document
        empty_stats = {
            "pkt_in": 0,
            "pkt_out": 0,
            "low_count": 0,
            "med_count": 0,
            "high_count": 0,
            "protocols_count": {},
            "services_count": {},
            "top_talkers": {},
            "top_ports": {},
            "top_attacked_ports": {},
            "top_attackers": {},
            "attack_type_count": {}
        }
        await mongodb_client.update_network_statistics(empty_stats)
        return {"status": "Network statistics reset successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reset network statistics: {str(e)}"
        )

@router.get("/non-normal-packets")
async def get_non_normal_packets(
    time_range: int = Query(30, description="Time range in minutes to fetch non-normal packets", ge=1, le=1440)
) -> List[Dict[str, Any]]:
    """
    Retrieve non-normal packets within a specified time range
    
    :param time_range: Time range in minutes to fetch packets (default: 30, max: 1440)
    :return: List of non-normal packets
    """
    try:
        from app.mongodb import mongodb_client
        packets = await mongodb_client.get_non_normal_packets(time_range)
        return packets
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve non-normal packets: {str(e)}"
        )
