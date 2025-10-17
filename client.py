# iiot_client/client.py
# FedIDS IIoT Client - cleaned & fixed
# Author: assistant (patch for Yasmine)
# Date: 2025-10-17

import os
import random
import time
import requests
import numpy as np
import threading
import argparse
import socket
from typing import Optional, Tuple

# ML imports
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import flwr as fl

# Import du modèle (essayer d'importer ATTACK_LABELS/NUM_CLASSES si présents)
try:
    from model_definition import create_model, ATTACK_LABELS, NUM_CLASSES
except Exception:
    try:
        from model_definition import create_model
    except Exception:
        raise
    # fallback si ATTACK_LABELS non fourni
    ATTACK_LABELS = [
        'Normal', 'Backdoor', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP', 'Password',
        'Port_Scanning', 'Ransomware', 'SQL_Injection', 'Spyware', 'Trojan',
        'Uploading', 'Vulnerability_Scan', 'XSS', 'MITM'
    ]
    NUM_CLASSES = len(ATTACK_LABELS)

# --- CONFIGURATION GLOBALE ---
# NOTE: model_definition.create_model should accept input shape compatible with generated data
TIME_STEPS, NUM_FEATURES = 20, 7
API_URL = "http://192.168.1.67:8000"
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"

REAL_WORLD_IPS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6", "4.2.2.2", "4.2.2.1",
    "195.8.215.68", "80.67.169.12", "213.73.91.35", "62.113.203.55", "80.241.218.68",
    "80.231.93.10", "85.214.20.141", "62.40.32.33", "212.27.40.240", "139.130.4.5",
    "61.9.194.49", "223.5.5.5", "114.114.114.114", "202.188.0.133", "210.220.163.82",
    "168.126.63.1", "203.80.96.10", "219.250.36.130", "59.124.1.30",
    "196.25.1.9", "197.149.150.5", "105.112.2.137", "212.14.253.242", "213.42.20.20",
    "196.200.160.1", "41.231.53.2", "41.65.236.56",
    "200.1.122.10", "200.160.0.8", "200.189.40.8", "190.93.189.30", "200.40.30.245",
    "201.148.95.234", "201.132.108.1", "200.11.52.202"
]

ATTACK_TYPES = ['Backdoor', 'DDoS_ICMP', 'DDoS_TCP', 'MITM', 'Port_Scanning', 'Ransomware']


# --- Fonctions utilitaires ---
def get_device_api_key(config_file: str) -> Optional[str]:
    """Lit la clé API depuis config.ini. Supporte plusieurs sections ('CLIENT' ou 'device')."""
    import configparser
    config = configparser.ConfigParser()
    config.read(config_file)
    # Priorité: section "device" then "CLIENT"
    if config.has_section('device') and config.has_option('device', 'api_key'):
        return config.get('device', 'api_key')
    if config.has_section('CLIENT') and config.has_option('CLIENT', 'api_key'):
        return config.get('CLIENT', 'api_key')
    # fallback generic
    return config.get('DEFAULT', 'api_key', fallback=None)


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


def register_client_to_backend(api_key: str, flower_cid: Optional[str] = None) -> None:
    """Enregistre le client auprès du backend (report optional flower_cid)."""
    try:
        payload = {"api_key": api_key}
        if flower_cid:
            payload["flower_cid"] = flower_cid
        response = requests.post(f"{API_URL}/api/fl/register", json=payload, timeout=5)
        if response.status_code == 200:
            print("✅ Client registered successfully with backend.")
        else:
            print(f"⚠️ Failed to register client. Status: {response.status_code}, Detail: {response.text}")
    except Exception as e:
        print(f"⚠️ Could not reach backend for client registration. Error: {e}")


# --- Background tasks (heartbeat, attack simulation, prevention) ---
def background_tasks(api_key: str, stop_event: threading.Event):
    """Thread qui envoie heartbeat, signale des attaques simulées et effectue des actions de prévention si activé."""

    prevention_enabled = False
    last_settings_check = 0

    def check_settings():
        nonlocal prevention_enabled, last_settings_check
        if time.time() - last_settings_check < 30:
            return
        last_settings_check = time.time()
        try:
            response = requests.get(f"{API_URL}/api/devices/{api_key}/settings", timeout=5)
            if response.status_code == 200:
                new_status = response.json().get("prevention_enabled", False)
                if new_status != prevention_enabled:
                    prevention_enabled = new_status
                    print(f"  > ✅ Prevention Status is now: {'ENABLED' if prevention_enabled else 'DISABLED'}")
            else:
                print(f"⚠️ Failed to check settings. Status code: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Error checking prevention settings: {e}")

    def run_prevention_action(ip_to_block: str, attack_type: str):
        action_message = f"Blocked traffic from {ip_to_block} due to {attack_type}."
        print(f"   🔥 PREMIUM PREVENTION: {action_message}")
        try:
            with open("firewall_rules.log", "a") as f:
                f.write(f"[{time.ctime()}] DENY IN FROM {ip_to_block} TO any\n")
        except Exception as e:
            print(f"⚠️ Error writing firewall log: {e}")
        try:
            requests.post(f"{API_URL}/api/devices/log-prevention", json={
                "api_key": api_key,
                "action_taken": action_message,
                "source_ip_blocked": ip_to_block,
                "attack_type_prevented": attack_type
            }, timeout=5)
            print("✅ Prevention action reported to backend.")
        except Exception as e:
            print(f"⚠️ Could not report prevention action: {e}")

    while not stop_event.is_set():
        try:
            check_settings()

            # Heartbeat
            try:
                requests.post(f"{API_URL}/api/devices/heartbeat", json={"api_key": api_key}, timeout=5)
                print(f"[Background] Heartbeat sent for device ...{api_key[-4:] if api_key else '----'}.")
            except Exception:
                try:
                    requests.post(f"{API_URL}/api/heartbeat", json={"api_key": api_key}, timeout=5)
                except Exception:
                    pass

            # Simulation d'attaque
            if random.random() > 0.6:
                attack_payload = {
                    "source_ip": random.choice(REAL_WORLD_IPS),
                    "attack_type": random.choice(ATTACK_TYPES if 'ATTACK_TYPES' in globals() else ATTACK_LABELS),
                    "confidence": round(random.uniform(0.96, 1.0), 2),
                    "api_key": api_key
                }
                print(f"🛑 [Background] Attack '{attack_payload['attack_type']}' from {attack_payload['source_ip']} reported (Confidence: {attack_payload['confidence']:.2f}).")
                try:
                    requests.post(f"{API_URL}/api/attacks/report", json=attack_payload, timeout=5)
                except Exception as e:
                    print(f"⚠️ Failed to report attack: {e}")

                if prevention_enabled and attack_payload['confidence'] > 0.95:
                    run_prevention_action(attack_payload['source_ip'], attack_payload['attack_type'])

            time.sleep(15)

        except Exception as e:
            print(f"⚠️ Error in background task loop: {e}")
            time.sleep(15)


# --- Génération des données locales ---
def generate_local_data(client_id: int, num_samples: int = 3000) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Génère des données locales simulées et les met à l'échelle.
    Chaque client a une distribution légèrement différente.
    NOTE: Adjust NUM_FEATURES/NUM_CLASSES to match your real model.
    """
    NUM_FEATURES = 24
    NUM_CLASSES = NUM_CLASSES if 'NUM_CLASSES' in globals() else 7

    np.random.seed(42 + client_id)
    random.seed(42 + client_id)

    X = np.random.rand(num_samples, NUM_FEATURES).astype(np.float32)
    y = np.random.randint(0, NUM_CLASSES, num_samples).astype(np.int32)

    # Slight client-specific bias (simulate non-iid)
    X += client_id * 0.02 * np.random.randn(*X.shape).astype(np.float32)

    # Scale features
    scaler = MinMaxScaler()
    X = scaler.fit_transform(X).reshape((num_samples, NUM_FEATURES, 1))

    # Stratified split when possible
    try:
        x_train, x_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    except Exception:
        x_train, x_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

    print(f"Client {client_id} → x_train: {x_train.shape}, y_train distribution: {np.unique(y_train, return_counts=True)}")
    return x_train, x_val, y_train, y_val


# --- Client Flower (implémentation consolidée) ---
class CnnLstmClient(fl.client.NumPyClient):
    def __init__(self, model, api_key: str, data: Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray], client_id: int):
        self.model = model
        self.api_key = api_key
        self.x_train, self.x_val, self.y_train, self.y_val = data
        self.client_id = client_id
        self.is_registered = False

    def get_parameters(self, config):
        # optionally register at first contact
        if not self.is_registered:
            try:
                # flower doesn't expose a client id here; keep safe attempt without assuming .cid
                payload = {"api_key": self.api_key}
                requests.post(f"{API_URL}/api/fl/register", json=payload, timeout=5)
                self.is_registered = True
                print(f"✅ Client {self.client_id} attempted registration with backend.")
            except Exception:
                pass
        return self.model.get_weights()

    def fit(self, parameters, config):
        self.model.set_weights(parameters)

        history = self.model.fit(
            self.x_train,
            self.y_train,
            epochs=8,
            batch_size=64,
            validation_split=0.1,
            verbose=1,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(monitor="val_loss", patience=2, restore_best_weights=True)
            ],
        )

        train_loss = float(history.history["loss"][-1])
        train_acc = float(history.history.get("accuracy", [0.0])[-1])

        print(f"✅ Client {self.client_id} - Local training done. Loss={train_loss:.4f}, Acc={train_acc:.4f}")

        # Return metrics so the server can aggregate them
        metrics = {"loss": train_loss, "accuracy": train_acc}
        return self.model.get_weights(), len(self.x_train), metrics

    def evaluate(self, parameters, config):
        self.model.set_weights(parameters)
        loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
        print(f"📊 Client {self.client_id} - Eval → Loss={loss:.4f}, Acc={accuracy:.4f}")
        return float(loss), len(self.x_val), {"accuracy": float(accuracy)}


# --- MAIN ---
def main():
    parser = argparse.ArgumentParser(description="FedIDS IIoT Client (Fixed)")
    parser.add_argument("--client-id", type=int, required=True)
    parser.add_argument("--config", type=str, default="config.ini")
    parser.add_argument("--server-ip", type=str, default="127.0.0.1")
    args = parser.parse_args()

    print(f"\n🚀 Starting FedIDS IIoT Client {args.client_id}\n")

    global API_URL, FLOWER_SERVER_ADDRESS
    API_URL = f"http://{args.server_ip}:8000"
    FLOWER_SERVER_ADDRESS = f"{args.server_ip}:8080"

    api_key = get_device_api_key(args.config)
    if not api_key:
        print(f"❌ FATAL: API Key not found in '{args.config}'. Exiting.")
        return

    # Start background thread
    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_tasks, args=(api_key, stop_event), daemon=True)
    bg_thread.start()
    print("✅ Background tasks (heartbeat, attack simulation) started.")

    # Generate data for this client
    data = generate_local_data(args.client_id)
    if not data:
        print("❌ Data generation failed. Exiting.")
        stop_event.set()
        bg_thread.join(1)
        return
    print(f"✅ Data generated: x_train={data[0].shape}, y_train={data[2].shape}")

    # Create model (server will send weights during FL)
    try:
        print("Creating model architecture from definition...")
        # create_model should match the data shape used in generate_local_data
        # If your create_model expects (TIME_STEPS, NUM_FEATURES), adjust generate_local_data accordingly.
        model = create_model()
        # Try loading initial weights if present (non-fatal)
        weights_path = "global_model.weights.h5"
        if os.path.exists(weights_path):
            try:
                model.load_weights(weights_path)
                print(f"Loaded initial weights from '{weights_path}'.")
            except Exception as e:
                print(f"⚠️ Could not load '{weights_path}': {e} — continuing without initial weights.")
        else:
            print("No initial global weights file found; continuing with freshly initialized model.")

        print("✅ Model created successfully.")
        model.summary()
    except Exception as e:
        print(f"❌ Failed to create/load model: {e}")
        stop_event.set()
        bg_thread.join(1)
        return

    # Create and start Flower client
    try:
        client = CnnLstmClient(model, api_key, data, client_id=args.client_id)
        print(f"Connecting to Flower server at {FLOWER_SERVER_ADDRESS}...")
        fl.client.start_numpy_client(server_address=FLOWER_SERVER_ADDRESS, client=client)
    except Exception as e:
        print(f"❌ Could not connect to Flower server: {e}")
    finally:
        print("Shutting down background tasks...")
        stop_event.set()
        bg_thread.join(2)
        print("✅ Client shutdown complete.")


if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    main()
