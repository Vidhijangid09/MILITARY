import os
import urllib.request
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump
import config

DATA_URL = 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt'
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label'
]


def download_dataset(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        print('Downloading dataset...')
        urllib.request.urlretrieve(DATA_URL, path)
        print('Dataset downloaded to', path)
    else:
        print('Dataset already exists at', path)


def load_and_prepare_data(path: str):
    df = pd.read_csv(path, names=COLUMN_NAMES, header=None)
    # Use only numeric features relevant for intrusion detection.
    numeric_features = [
        'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate'
    ]
    # Coerce any non-numeric entries to NaN then fill with 0 to avoid conversion errors
    df_numeric = df[numeric_features].apply(lambda col: pd.to_numeric(col, errors='coerce')).fillna(0)
    return df_numeric


def train_model(data_frame: pd.DataFrame):
    scaler = StandardScaler()
    X = scaler.fit_transform(data_frame)
    model = IsolationForest(n_estimators=150, contamination='auto', random_state=42)
    model.fit(X)
    return model, scaler


def save_model(model, scaler):
    os.makedirs(os.path.dirname(config.THREAT_MODEL_PATH), exist_ok=True)
    dump({'model': model, 'scaler': scaler}, config.THREAT_MODEL_PATH)
    print('Threat detection model saved to', config.THREAT_MODEL_PATH)


def main():
    dataset_path = os.path.join(os.path.dirname(__file__), 'KDDTrain+.txt')
    download_dataset(dataset_path)
    data_frame = load_and_prepare_data(dataset_path)
    model, scaler = train_model(data_frame)
    save_model(model, scaler)


if __name__ == '__main__':
    main()
