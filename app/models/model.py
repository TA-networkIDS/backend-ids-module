import numpy as np
import tensorflow as tf
import os
import joblib

from app.preprocessing.preprocessing import preprocess_data

# Multi-Class
model_path = os.path.join(os.path.dirname(__file__), '../../trained_models/dnn/0705/model.h5')
label_encoder_path = os.path.join(os.path.dirname(__file__), '../../trained_models/dnn/0705/label_encoder.pkl')
model = tf.keras.models.load_model(model_path)
label_encoder = joblib.load(label_encoder_path) 


def predict(data_list):
    processed_features = preprocess_data(data_list)
    predictions = model.predict(processed_features)
    predicted_class_indices = np.argmax(predictions, axis=1)
    confidences = np.max(predictions, axis=1)
    
    predicted_class_labels = label_encoder.inverse_transform(predicted_class_indices).tolist()
    
    results = []
    for label, confidence in zip(predicted_class_labels, confidences):
        results.append({
            'predicted_class': label,
            'confidence': float(confidence)
        })
    
    return results