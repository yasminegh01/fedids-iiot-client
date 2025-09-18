# iiot_client/client.py

import flwr as fl
import tensorflow as tf
import numpy as np
from sklearn.model_selection import train_test_split
import argparse
import os
import configparser
import requests
import time
import threading
from typing import Optional

# --- Configuration Globale ---
API_URL = "http://127.0.0.1:8000" 
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"

# Configuration du modèle et des données simulées
TIME_STEPS = 20
NUM_FEATURES = 7
NUM_CLASSES = 15 # Le nombre total de types d'attaques + 'Normal'

# --- Fonctions Utilitaires ---

def get_device_api_key(config_file: str) -> Optional[str]:
    """Lit la clé API depuis le fichier de configuration."""
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        print(f"Error: Config file '{config_file}' not found.")
        return None
    config.read(config_file)
    return config.get('device', 'api_key', fallback=None)

def send_heartbeat(api_key: str, stop_event: threading.Event):
    """Envoie un "heartbeat" périodique au backend."""
    while not stop_event.is_set():
        if api_key:
            try:
                requests.post(f"{API_URL}/api/devices/heartbeat", json={"api_key": api_key}, timeout=10)
                print(f"[Heartbeat] Ping sent for ...{api_key[-4:]}.")
            except requests.exceptions.RequestException:
                print("[Heartbeat] Warning: Could not reach backend server.")
        time.sleep(60)

# --- Simulation de Données Locales ---

def generate_local_data(num_samples=1000):
    """
    Crée un petit jeu de données local et privé pour ce client.
    Pas besoin de CSV, tout est généré en mémoire.
    """
    print(f"Generating {num_samples} local data samples for training...")
    # Simuler des données brutes (valeurs normalisées entre 0 et 1)
    X_raw = np.random.rand(num_samples, NUM_FEATURES)
    # Simuler des étiquettes (0 pour normal, 1-14 pour les attaques)
    y_raw = np.random.randint(0, NUM_CLASSES, size=num_samples)
    
    # Créer des séquences temporelles
    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:(i + TIME_STEPS)])
        ys.append(y_raw[i + TIME_STEPS])
    
    if not Xs:
        print("Error: Not enough data to create sequences.")
        return None
        
    X_seq, y_seq = np.array(Xs), np.array(ys)
    return train_test_split(X_seq, y_seq, test_size=0.2, random_state=42)

# --- Client Flower ---
class CnnLstmClient(fl.client.NumPyClient):
    def __init__(self, model, x_train, y_train, x_val, y_val):
        self.model = model
        self.x_train, self.y_train = x_train, y_train
        self.x_val, self.y_val = x_val, y_val

    def get_parameters(self, config):
        return self.model.get_weights()

    def fit(self, parameters, config):
        self.model.set_weights(parameters)
        self.model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
        self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=0)
        print("✅ Local training round finished.")
        return self.model.get_weights(), len(self.x_train), {}

    def evaluate(self, parameters, config):
        self.model.set_weights(parameters)
        self.model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
        loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
        return float(loss), len(self.x_val), {"accuracy": float(accuracy)}

# --- Fonction Principale ---
def main():
    parser = argparse.ArgumentParser(description="FedIds IIoT Client")
    parser.add_argument("--client-id", type=int, required=True, help="Client ID (e.g., 0)")
    parser.add_argument("--config", type=str, default="config.ini", help="Path to config file")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1", help="IP address of the main server")
    args = parser.parse_args()

    print(f"--- Starting Client {args.client_id} (Config: {args.config}) ---")

    global API_URL, FLOWER_SERVER_ADDRESS
    API_URL = f"http://{args.server_ip}:8000"
    FLOWER_SERVER_ADDRESS = f"{args.server_ip}:8080"

    api_key = get_device_api_key(args.config)
    if not api_key:
        print(f"❌ FATAL: API Key not found in '{args.config}'. Exiting.")
        return

    print("✅ API Key found. Starting heartbeat thread...")
    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(target=send_heartbeat, args=(api_key, stop_event), daemon=True)
    heartbeat_thread.start()

    print("Simulating local private data...")
    data = generate_local_data()
    if data is None:
        print("❌ Data generation failed. Exiting.")
        return
    x_train, x_val, y_train, y_val = data
    
    try:
        model = tf.keras.models.load_model('global_model.h5')
    except Exception as e:
        print(f"❌ Failed to load model 'global_model.h5': {e}")
        return

    client = CnnLstmClient(model, x_train, y_train, x_val, y_val)
    
    print(f"Connecting to Flower server at {FLOWER_SERVER_ADDRESS}...")
    try:
        fl.client.start_client(server_address=FLOWER_SERVER_ADDRESS, client=client)
    except Exception as e:
        print(f"❌ Could not connect to Flower server: {e}")
    finally:
        print("Shutting down client...")
        stop_event.set()
        heartbeat_thread.join(2)

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    main()