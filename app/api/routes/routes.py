# REST API for testing model and network statistics

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Optional
from app.models.model import predict
from app.network_statistics import network_stats_service

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
async def get_network_statistics(request: Request):
    """
    Retrieve network statistics from MongoDB
    
    Returns:
    - Packet counts
    - Protocol distribution
    - Service distribution
    - Attack type distribution
    - Top talkers, ports, and attackers
    """
    try:
        return await request.app.mongodb.get_network_statistics()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve network statistics: {str(e)}"
        )

@router.get("/packets")
async def get_packets():
    """
    Retrieve all stored packets
    
    Returns:
    - All Packets
    """
    try:
        return network_stats_service.get_all_packets()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve packets: {str(e)}"
        )

@router.get("/non-normal-packets")
async def get_non_normal_packets(
    request: Request,
    time_range: Optional[int] = Query(30, description="Time range in minutes")
):
    """
    Retrieve non-normal packets from MongoDB
    
    Parameters:
    - time_range: Time range in minutes to fetch packets (default: 30)
    
    Returns:
    - List of non-normal packets within the specified time range
    """
    try:
        return await request.app.mongodb.get_non_normal_packets(time_range)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve non-normal packets: {str(e)}"
        )
