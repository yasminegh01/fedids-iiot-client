

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
TIME_STEPS, NUM_FEATURES = 20, 7
# API/Flower seront définis au runtime via les arguments
API_URL = "http://127.0.0.1:8000"
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"

# Liste d'IPs (fusion des deux listes pour couvrir plus de cas)
REAL_WORLD_IPS = [
    # Root / anycast / providers (extrait combiné)
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

# Types d'attaques (utilisé localement si ATTACK_LABELS non fourni)
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

            # Heartbeat (essayons plusieurs endpoints possibles pour compatibilité)
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
def generate_local_data(num_samples: int = 3000) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Génère des séquences temporelles normalisées. Retourne train_test_split (x_train, x_val, y_train, y_val).
    Utilise ATTACK_LABELS s'il est disponible dans model_definition, sinon utilise la liste interne.
    """
    print(f"Generating {num_samples} enhanced semi-realistic data samples...")

    signatures = {
        'Normal': [(0, 0.0, 0.2), (1, 0.1, 0.3)],
        'Backdoor': [(4, 0.8, 1.0), (6, 0.6, 0.9)],
        'DDoS_TCP': [(2, 0.9, 1.0), (3, 0.8, 0.95)],
        'DDoS_UDP': [(2, 0.85, 1.0), (3, 0.8, 0.9)],
        'DDoS_HTTP': [(2, 0.8, 1.0), (5, 0.7, 0.9)],
        'DDoS_ICMP': [(1, 0.8, 1.0), (2, 0.8, 1.0)],
        'Port_Scanning': [(0, 0.7, 0.9), (1, 0.8, 1.0)],
        'MITM': [(0, 0.9, 1.0), (3, 0.7, 0.85)],
        'Ransomware': [(5, 0.8, 1.0), (6, 0.8, 1.0)],
        'SQL_Injection': [(3, 0.7, 0.9), (5, 0.8, 1.0)],
        'XSS': [(3, 0.6, 0.8), (5, 0.8, 0.9)],
        'Fingerprinting': [(1, 0.6, 0.8), (2, 0.7, 0.9)],
        'Password': [(5, 0.9, 1.0)],
        'Uploading': [(6, 0.8, 1.0)],
        'Vulnerability_scanner': [(0, 0.6, 0.8), (1, 0.7, 0.9)],
    }

    X_raw, y_raw = [], []

    labels = ATTACK_LABELS if 'ATTACK_LABELS' in globals() else ATTACK_TYPES

    for _ in range(num_samples):
        attack_type = random.choice(labels)
        label_index = labels.index(attack_type)

        # Bruit aléatoire global pour variabilité
        features = np.random.normal(0.2, 0.05, NUM_FEATURES)

        # Ajouter signatures
        for idx, min_val, max_val in signatures.get(attack_type, []):
            features[idx] = random.uniform(min_val, max_val)

        # Corrélation simulée
        correlated_idx = random.sample(range(NUM_FEATURES), 2)
        features[correlated_idx[1]] = features[correlated_idx[0]] * random.uniform(0.8, 1.2)

        X_raw.append(features)
        y_raw.append(label_index)

    # Normalisation
    scaler = MinMaxScaler()
    X_raw = scaler.fit_transform(np.array(X_raw))

    # Séquences temporelles
    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:i + TIME_STEPS])
        ys.append(y_raw[i + TIME_STEPS])

    Xs = np.array(Xs)
    ys = np.array(ys)

    return train_test_split(Xs, ys, test_size=0.2, random_state=42)


# --- Client Flower (implémentation consolidée) ---
class CnnLstmClient(fl.client.NumPyClient):
    def __init__(self, model, api_key, data):
        self.model = model
        self.api_key = api_key
        self.x_train, self.x_val, self.y_train, self.y_val = data
        self.is_registered = False

    def get_parameters(self, config):
        # === CORRECTION DU BUG 422 ===
        # C'est le premier endroit où nous avons accès au `cid` du client.
        # On en profite pour s'enregistrer auprès du backend.
        if not self.is_registered and hasattr(self, 'cid'):
            try:
                payload = {"api_key": self.api_key, "flower_cid": self.cid}
                requests.post(f"{API_URL}/api/fl/register", json=payload, timeout=5)
                print(f"✅ Successfully registered client {self.cid} with backend.")
                self.is_registered = True
            except Exception as e:
                print(f"⚠️ Could not register client with backend. Error: {e}")
        return self.model.get_weights()

    def fit(self, parameters, config):
        self.model.set_weights(parameters)
        # Utiliser des callbacks pour un meilleur entraînement
        early_stop = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)
        self.model.fit(
            self.x_train, self.y_train,
            epochs=6, batch_size=32,
            validation_split=0.1, # Utiliser une partie des données d'entraînement pour la validation
            callbacks=[early_stop],
            verbose=1
        )
        return self.model.get_weights(), len(self.x_train), {}
    def evaluate(self, parameters, config):
        self.model.set_weights(parameters)
        loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
        print(f"📊 Evaluation — Loss: {loss:.4f}, Accuracy: {accuracy:.4f}")
        return float(loss), len(self.x_val), {"accuracy": float(accuracy)}


# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="FedIDS IIoT Client (combined)")
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

    # Démarrer tâches de fond
    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_tasks, args=(api_key, stop_event), daemon=True)
    bg_thread.start()
    print("✅ Background tasks (heartbeat, attack simulation) started.")

    # Génération données
    #x_train, x_val, y_train, y_val = generate_local_data()
    data = generate_local_data()
    #print(f"✅ Data: x_train={x_train.shape}, y_train={y_train.shape}, x_val={x_val.shape}, y_val={y_val.shape}")

    # Création du modèle
    model = create_model()
    print(model.summary())

    # Enregistrement auprès du backend
    register_client_to_backend(api_key)

    # Création client Flower
    client = CnnLstmClient(model, api_key, data)

    print(f"Connecting to Flower server at {FLOWER_SERVER_ADDRESS}...")
    try:
        # La nouvelle façon recommandée d'appeler le client
        fl.client.start_client(server_address=FLOWER_SERVER_ADDRESS, client=client.to_client())
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
