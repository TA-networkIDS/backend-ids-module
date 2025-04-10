# REST API for testing model

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.models.model import predict

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
