# REST API for testing model and network statistics

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
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
async def get_network_statistics():
    """
    Retrieve current network statistics
    
    Returns:
    - Packet counts
    - Protocol distribution
    - Service distribution
    - Attack type distribution
    - Top talkers, ports, and attackers
    """
    try:
        return network_stats_service.get_statistics()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve network statistics: {str(e)}"
        )

@router.post("/reset-network-statistics")
async def reset_network_statistics():
    """
    Reset all network statistics
    """
    try:
        network_stats_service.reset_statistics()
        return {"status": "Network statistics reset successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reset network statistics: {str(e)}"
        )
