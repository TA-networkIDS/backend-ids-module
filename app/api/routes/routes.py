from fastapi import APIRouter
from pydantic import BaseModel
from app.models.model import predict 

router = APIRouter()

class Features(BaseModel):
    features: list

@router.post("/predict")
def predict_route(data: Features):
    prediction = predict(data.features)
    return prediction