import numpy as np
import tensorflow as tf
import os
import joblib 

model_path = os.path.join(os.path.dirname(__file__), '../../trained_models/model.h5')
label_encoder_path = os.path.join(os.path.dirname(__file__), '../../trained_models/label_encoder.pkl')
model = tf.keras.models.load_model(model_path)
label_encoder = joblib.load(label_encoder_path) 


def preprocess_data(data):
    processed_data = np.array(data)
    if processed_data.ndim == 1:
        processed_data = processed_data.reshape(1, -1)
    return processed_data

def predict(features):
    processed_features = preprocess_data(features)
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