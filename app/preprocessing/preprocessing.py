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

# Multi-Class
preprocessor_path = os.path.join(os.path.dirname(__file__), '../../trained_models/2904/preprocessor.joblib')
preprocessor = joblib.load(preprocessor_path)

# Binary-Class
# preprocessor_path = os.path.join(os.path.dirname(__file__), '../../trained_models/binary1704/preprocessor.joblib')
# preprocessor = joblib.load(preprocessor_path)

def preprocess_data(data_list):
    """Process a batch of network feature dictionaries"""
    df = pd.DataFrame(data_list)
    
    df['service'] = df['service'].apply(
        lambda x: x if x in PREDEFINED_SERVICES else 'other'
    )
    
    processed_data = preprocessor.transform(df)
    
    return processed_data