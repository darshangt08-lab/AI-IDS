import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle
import os

# NSL-KDD Feature Names
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

def generate_synthetic_data(num_samples=2000):
    """
    Generates synthetic data mimicking NSL-KDD for training if the dataset isn't present.
    In a real project, the user would provide the CSV.
    """
    data = []
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'dns', 'ssh']
    flags = ['SF', 'S0', 'REJ', 'RSTO']
    
    for _ in range(num_samples):
        is_intrusion = np.random.choice([0, 1], p=[0.7, 0.3])
        
        protocol = np.random.choice(protocols)
        service = np.random.choice(services)
        flag = np.random.choice(flags)
        
        if is_intrusion:
            src_bytes = np.random.randint(1000, 50000)
            dst_bytes = np.random.randint(1000, 50000)
            duration = np.random.randint(500, 5000)
            label = 'anomaly'
        else:
            src_bytes = np.random.randint(100, 1000)
            dst_bytes = np.random.randint(100, 1000)
            duration = np.random.randint(0, 100)
            label = 'normal'
            
        row = [duration, protocol, service, flag, src_bytes, dst_bytes] + [0]*35 + [label, 21]
        data.append(row)
        
    return pd.DataFrame(data, columns=columns)

def train_model():
    print("Generating/Loading dataset...")
    df = generate_synthetic_data(5000)
    
    # We will use exactly the features required for manual analysis for simplicity in this demo
    # Features: protocol_type, service, flag, src_bytes, dst_bytes, duration
    features = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'duration']
    X = df[features]
    y = df['label'].apply(lambda x: 1 if x != 'normal' else 0)
    
    # Encoding categorical features
    encoders = {}
    for col in ['protocol_type', 'service', 'flag']:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        encoders[col] = le
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Save model and encoders
    model_data = {
        'model': model,
        'encoders': encoders,
        'features': features
    }
    
    with open('model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
        
    print("Model saved to model.pkl")

if __name__ == "__main__":
    train_model()
