import pandas as pd
import numpy as np
import joblib
import os

PREDEFINED_SERVICES = {
    'smtp', 'uucp', 'ftp', 'http', 'iso_tsap', 'vmnet', 'private', 'nnsp',
    'urp_i', 'whois', 'domain_u', 'domain', 'auth', 'bgp', 'uucp_path',
    'telnet', 'other', 'time', 'Z39_50', 'finger', 'eco_i', 'ecr_i',
    'courier', 'ftp_data', 'imap4'
}

# Based on first reference paper
# This will not be used when new trained model uploaded
SELECTED_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Multi-Class
preprocessor_path = os.path.join(os.path.dirname(__file__), '../../trained_models/dnn/2904/preprocessor.joblib')
preprocessor = joblib.load(preprocessor_path)


def preprocess_data(data_list):
    """Process a batch of network feature dictionaries"""
    # This [SELECTED_FEATURES] is temporary for the current trained model
    df = pd.DataFrame(data_list)[SELECTED_FEATURES]
    
    df['service'] = df['service'].apply(
        lambda x: x if x in PREDEFINED_SERVICES else 'other'
    )
    
    processed_data = preprocessor.transform(df)
    
    return processed_data