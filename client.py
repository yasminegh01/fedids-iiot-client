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
import geoip2.database

# --- Configuration Globale ---
API_URL = "http://127.0.0.1:8000"
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"
TIME_STEPS = 20
NUM_FEATURES = 7
NUM_CLASSES = 15  # Attaques + Normal
REAL_WORLD_IPS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12",
    "8.8.8.8", "1.1.1.1", "9.9.9.9",
    "195.8.215.68", "212.14.253.242", "213.42.20.20"
]  # Exemple simplifié

ATTACK_TYPES = ['Backdoor','DDoS_ICMP','DDoS_TCP','MITM','Port_Scanning','Ransomware']

# --- Fonctions Utilitaires ---
def get_device_api_key(config_file: str) -> Optional[str]:
    config = configparser.ConfigParser()
    if not os.path.exists(config_file):
        print(f"❌ Error: Config file '{config_file}' not found.")
        return None
    config.read(config_file)
    return config.get('device', 'api_key', fallback=None)

def send_heartbeat(api_key: str, stop_event: threading.Event):
    while not stop_event.is_set():
        if api_key:
            try:
                requests.post(f"{API_URL}/api/devices/heartbeat", json={"api_key": api_key}, timeout=10)
                print(f"[Heartbeat] Ping sent for ...{api_key[-4:]}.")
            except requests.exceptions.RequestException:
                print("[Heartbeat] Warning: Could not reach backend server.")
        time.sleep(60)

def generate_local_data(num_samples=1000):
    print(f"Generating {num_samples} local data samples for training...")
    X_raw = np.random.rand(num_samples, NUM_FEATURES)
    y_raw = np.random.randint(0, NUM_CLASSES, size=num_samples)
    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:(i + TIME_STEPS)])
        ys.append(y_raw[i + TIME_STEPS])
    if not Xs:
        print("❌ Error: Not enough data to create sequences.")
        return None
    X_seq, y_seq = np.array(Xs), np.array(ys)
    return train_test_split(X_seq, y_seq, test_size=0.2, random_state=42)

def geolocate_ip(ip: str):
    """Retourne (country, city) pour une IP."""
    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")  # Assurez-vous d'avoir ce fichier
        response = reader.city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        reader.close()
        return country, city
    except Exception:
        return "Unknown", "Unknown"

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
        self.model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=0)
        print("✅ Local training round finished.")
        return self.model.get_weights(), len(self.x_train), {}

    def evaluate(self, parameters, config):
        self.model.set_weights(parameters)
        self.model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
        return float(loss), len(self.x_val), {"accuracy": float(accuracy)}

# --- Fonction Principale ---
def main():
    parser = argparse.ArgumentParser(description="FedIds IIoT Client")
    parser.add_argument("--client-id", type=int, required=True)
    parser.add_argument("--config", type=str, default="config.ini")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1")
    args = parser.parse_args()

    global API_URL, FLOWER_SERVER_ADDRESS
    API_URL = f"http://{args.server_ip}:8000"
    FLOWER_SERVER_ADDRESS = f"{args.server_ip}:8080"

    api_key = get_device_api_key(args.config)
    if not api_key:
        print(f"❌ FATAL: API Key not found in '{args.config}'. Exiting.")
        return

    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(target=send_heartbeat, args=(api_key, stop_event), daemon=True)
    heartbeat_thread.start()

    data = generate_local_data()
    if data is None:
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
        stop_event.set()
        heartbeat_thread.join(2)

    # --- Simulation d'attaques avec géolocalisation ---
    for _ in range(5):  # Exemple: 5 détections
        attack_type = np.random.choice(ATTACK_TYPES)
        source_ip = np.random.choice(REAL_WORLD_IPS)
        confidence = round(np.random.uniform(0.85, 1.0), 2)
        country, city = geolocate_ip(source_ip)
        report_payload = {
            "source_ip": source_ip,
            "attack_type": attack_type,
            "confidence": float(confidence),
            "country": country,
            "city": city
        }
        try:
            requests.post(f"{API_URL}/api/attacks/report", json=report_payload, timeout=5)
            print(f"🛑 Attack '{attack_type}' from {source_ip} ({country}, {city}) reported.")
        except Exception as e:
            print(f"⚠️ Failed to report attack: {e}")

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    main()
