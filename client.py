# iiot_client/client.py

import flwr as fl
import tensorflow as tf
import numpy as np
import argparse, os, configparser, requests, time, threading, random, socket
from typing import Optional
from sklearn.model_selection import train_test_split
from model_definition import create_model

# --- Configuration Globale ---
API_URL = "http://127.0.0.1:8000"
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"
TIME_STEPS, NUM_FEATURES, NUM_CLASSES = 20, 7, 15
REAL_WORLD_IPS = [
    "8.8.8.8", "1.1.1.1", "195.8.215.68", "139.130.4.5", "202.12.27.33"
]
ATTACK_TYPES = ['Backdoor', 'DDoS_ICMP', 'DDoS_TCP', 'MITM', 'Port_Scanning', 'Ransomware']

# --- Fonctions Utilitaires ---
def get_device_api_key(config_file: str) -> Optional[str]:
    config = configparser.ConfigParser()
    config.read(config_file)
    return config.get('device', 'api_key', fallback=None)

def get_local_ip() -> str:
    """Retourne l'adresse IP locale de la machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def background_tasks(api_key: str, stop_event: threading.Event):
    """Thread pour heartbeat et simulation d'attaques."""
    local_ip = get_local_ip()
    while not stop_event.is_set():
        try:
            heartbeat_data = {"api_key": api_key, "ip": local_ip}
            requests.post(f"{API_URL}/api/devices/heartbeat", json=heartbeat_data, timeout=5)
            print(f"[Background] Heartbeat sent from IP {local_ip} for ...{api_key[-4:]}.")
        except Exception as e:
            print(f"[Background] Heartbeat error: {e}")

        if random.random() > 0.7:
            attack = {
                "source_ip": random.choice(REAL_WORLD_IPS),
                "attack_type": random.choice(ATTACK_TYPES),
                "confidence": round(random.uniform(0.8, 1.0), 2),
                "api_key": api_key 
            }
            try:
                requests.post(f"{API_URL}/api/attacks/report", json=attack, timeout=5)
                print(f"🛑 [Background] Attack '{attack['attack_type']}' from {attack['source_ip']} reported.")
            except Exception as e:
                print(f"[Background] Attack reporting error: {e}")

        time.sleep(30)

def generate_local_data(num_samples=1000):
    print(f"Generating {num_samples} local data samples for training...")
    X_raw = np.random.rand(num_samples, NUM_FEATURES)
    y_raw = np.random.randint(0, NUM_CLASSES, size=num_samples)
    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:(i + TIME_STEPS)])
        ys.append(y_raw[i + TIME_STEPS])
    if not Xs:
        return None
    return train_test_split(np.array(Xs), np.array(ys), test_size=0.2, random_state=42)

# --- Client Flower ---
class CnnLstmClient(fl.client.NumPyClient):
    def __init__(self, model, x_train, y_train, x_val, y_val):
        self.model = model
        self.x_train, self.y_train = x_train, y_train
        self.x_val, self.y_val = x_val, y_val

    def get_parameters(self, config):
        return self.model.get_weights()

    def fit(self, parameters, config):
        try:
            self.model.set_weights(parameters)
            self.model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
            self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=1)
            print("✅ Local training round finished.")
            return self.model.get_weights(), len(self.x_train), {}
        except Exception as e:
            print(f"❌ Error in fit(): {e}")
            return self.model.get_weights(), 0, {}

    def evaluate(self, parameters, config):
        try:
            self.model.set_weights(parameters)
            self.model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
            loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
            return float(loss), len(self.x_val), {"accuracy": float(accuracy)}
        except Exception as e:
            print(f"❌ Error in evaluate(): {e}")
            return 0.0, 0, {"accuracy": 0.0}

# --- Fonction Principale ---
def main():
    parser = argparse.ArgumentParser(description="FedIds IIoT Client")
    parser.add_argument("--client-id", type=int, required=True)
    parser.add_argument("--config", type=str, default="config.ini")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1")
    args = parser.parse_args()

    print(f"--- Starting Client {args.client_id} (Config: {args.config}) ---")

    global API_URL, FLOWER_SERVER_ADDRESS
    API_URL = f"http://{args.server_ip}:8000"
    FLOWER_SERVER_ADDRESS = f"{args.server_ip}:8080"

    api_key = get_device_api_key(args.config)
    if not api_key:
        print(f"❌ FATAL: API Key not found in '{args.config}'. Exiting.")
        return

    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_tasks, args=(api_key, stop_event), daemon=True)
    bg_thread.start()
    print("✅ Background tasks (heartbeat, attack simulation) started.")

    data = generate_local_data()
    if not data:
        print("❌ Data generation failed. Exiting.")
        stop_event.set()
        return
    x_train, x_val, y_train, y_val = data
    print(f"✅ Data generated: x_train={x_train.shape}, y_train={y_train.shape}, x_val={x_val.shape}, y_val={y_val.shape}")

    try:
        print("Creating model architecture from definition...")
        model = create_model()
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        print(model.summary())
        print("✅ Model created and compiled (weights will come from server).")
    except Exception as e:
        print(f"❌ Failed to create model: {e}")
        stop_event.set()
        bg_thread.join(1)
        return

    client = CnnLstmClient(model, x_train, y_train, x_val, y_val)
    print(f"Connecting to Flower server at {FLOWER_SERVER_ADDRESS}...")
    try:
        fl.client.start_client(server_address=FLOWER_SERVER_ADDRESS, client=client)
    except Exception as e:
        print(f"❌ Could not connect to Flower server: {e}")
    finally:
        print("Shutting down background tasks...")
        stop_event.set()
        bg_thread.join(2)

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    main()
