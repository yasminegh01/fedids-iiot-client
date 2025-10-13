#Git 

# iiot_client/client.py

import flwr as fl
import tensorflow as tf
import numpy as np
import argparse, os, configparser, requests, time, threading, random, socket
from typing import Optional
from sklearn.model_selection import train_test_split
from model_definition import create_model, ATTACK_LABELS, NUM_CLASSES

# --- Configuration Globale ---
API_URL = "http://127.0.0.1:8000"
FLOWER_SERVER_ADDRESS = "127.0.0.1:8080"
TIME_STEPS, NUM_FEATURES, NUM_CLASSES = 20, 7, 15
REAL_WORLD_IPS = [
    # ---------------------------
    # 🌍 ROOT DNS SERVERS (A–M)
    # ---------------------------
    "198.41.0.4",     # A-root (Verisign, USA)
    "199.9.14.201",   # B-root (ISI, USA)
    "192.33.4.12",    # C-root (Cogent, USA)
    "199.7.91.13",    # D-root (UMD, USA)
    "192.203.230.10", # E-root (NASA, USA)
    "192.5.5.241",    # F-root (ISC, USA)
    "192.112.36.4",   # G-root (US DoD NIC)
    "198.97.190.53",  # H-root (U.S. Army Research Lab)
    "192.36.148.17",  # I-root (Netnod, Sweden)
    "192.58.128.30",  # J-root (Verisign, USA)
    "193.0.14.129",   # K-root (RIPE NCC, Netherlands)
    "199.7.83.42",    # L-root (ICANN, Global)
    "202.12.27.33",   # M-root (WIDE, Japan)

    # ---------------------------
    # 🌐 GLOBAL ANYCAST RESOLVERS
    # ---------------------------
    "8.8.8.8",        # Google DNS (Global)
    "8.8.4.4",        # Google Secondary
    "1.1.1.1",        # Cloudflare DNS
    "1.0.0.1",        # Cloudflare Secondary
    "9.9.9.9",        # Quad9 (Switzerland, Anycast)
    "149.112.112.112",# Quad9 Secondary
    "208.67.222.222", # OpenDNS (Cisco, USA)
    "208.67.220.220", # OpenDNS Secondary
    "64.6.64.6",      # Verisign DNS
    "64.6.65.6",      # Verisign Secondary
    "4.2.2.2",        # Level 3 (USA)
    "4.2.2.1",        # Level 3 Secondary

    # ---------------------------
    # 🇺🇸 NORTH AMERICA
    # ---------------------------
    "12.127.17.72",   # AT&T (USA)
    "198.6.1.122",    # Verizon (USA)
    "24.113.32.30",   # Cox (USA)
    "209.18.47.61",   # Time Warner Cable (USA)
    "199.85.126.10",  # Neustar UltraDNS

    # ---------------------------
    # 🇪🇺 EUROPE
    # ---------------------------
    "195.8.215.68",   # Orange (France)
    "80.67.169.12",   # FDN (France)
    "213.73.91.35",   # Deutsche Telekom (Germany)
    "62.113.203.55",  # Vodafone (Germany)
    "80.241.218.68",  # XS4ALL (Netherlands)
    "80.231.93.10",   # Telecom Italia (Italy)
    "85.214.20.141",  # Strato (Germany)
    "62.40.32.33",    # GARR (Italy)
    "212.27.40.240",  # Free (France)

    # ---------------------------
    # 🌏 ASIA-PACIFIC
    # ---------------------------
    "139.130.4.5",    # Telstra (Australia)
    "61.9.194.49",    # Optus (Australia)
    "223.5.5.5",      # AliDNS (China)
    "114.114.114.114",# 114DNS (China)
    "202.188.0.133",  # NTT (Japan)
    "210.220.163.82", # Korea Telecom (South Korea)
    "168.126.63.1",   # KRNIC (Korea)
    "203.80.96.10",   # Singtel (Singapore)
    "219.250.36.130", # SK Broadband (Korea)
    "59.124.1.30",    # HiNet (Taiwan)

    # ---------------------------
    # 🌍 AFRICA & MIDDLE EAST
    # ---------------------------
    "196.25.1.9",     # Telkom SA (South Africa)
    "197.149.150.5",  # MTN (Nigeria)
    "105.112.2.137",  # Glo Mobile (Nigeria)
    "212.14.253.242", # STC (Saudi Arabia)
    "213.42.20.20",   # Etisalat (UAE)
    "196.200.160.1",  # Maroc Telecom (Morocco)
    "41.231.53.2",    # Tunisie Telecom (Tunisia)
    "41.65.236.56",   # TE Data (Egypt)

    # ---------------------------
    # 🌎 LATIN AMERICA
    # ---------------------------
    "200.1.122.10",   # Telefonica (Brazil)
    "200.160.0.8",    # NIC.br (Brazil)
    "200.189.40.8",   # Embratel (Brazil)
    "190.93.189.30",  # Claro (Argentina)
    "200.40.30.245",  # Antel (Uruguay)
    "201.148.95.234", # Movistar (Chile)
    "201.132.108.1",  # Telmex (Mexico)
    "200.11.52.202",  # CNT (Ecuador)
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


def register_client_to_backend(api_key: str, flower_cid: str):
    """Annonce ce client au backend pour le lier à un utilisateur."""
    try:
        # Le Pydantic Model FLClientRegistration attend 'api_key' et 'flower_cid'
        payload = {"api_key": api_key, "flower_cid": flower_cid}
        response = requests.post(f"{API_URL}/api/fl/register", json=payload, timeout=5)
        if response.status_code == 200:
            print(f"✅ Successfully registered client {flower_cid} with backend.")
        else:
            # On affiche le détail de l'erreur renvoyée par FastAPI
            print(f"⚠️ Warning: Failed to register client. Status: {response.status_code}, Detail: {response.text}")
    except Exception as e:
        print(f"⚠️ Warning: Could not reach backend for client registration. Error: {e}")


def background_tasks(api_key: str, stop_event: threading.Event):
    """Thread pour le heartbeat, la simulation d'attaques et la prévention."""

    prevention_enabled = False
    last_settings_check = 0

    def check_settings():
        """Vérifie périodiquement si la prévention est activée sur le backend."""
        nonlocal prevention_enabled, last_settings_check
        if time.time() - last_settings_check < 30:
            return  # Vérifie toutes les 30 secondes

        print("\n[Background] Checking for new prevention settings...")
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

    def run_prevention_action(ip_to_block, attack_type):
        """Bloque une IP, log et reporte l'action au backend."""
        action_message = f"Blocked traffic from {ip_to_block} due to {attack_type}."
        print(f"   🔥 PREMIUM PREVENTION: {action_message}")

        # Écriture dans un fichier log local
        try:
            with open("firewall_rules.log", "a") as f:
                f.write(f"[{time.ctime()}] DENY IN FROM {ip_to_block} TO any\n")
        except Exception as e:
            print(f"⚠️ Error writing firewall log: {e}")

        # Reporter l'action au backend
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
            # 1. Vérifier les réglages
            check_settings()

            # 2. Heartbeat
            try:
                requests.post(f"{API_URL}/api/devices/heartbeat", json={"api_key": api_key}, timeout=5)
                print(f"[Background] Heartbeat sent for device ...{api_key[-4:]}.")
            except Exception as e:
                print(f"⚠️ Heartbeat failed: {e}")

            # 3. Simulation d'attaque
            if random.random() > 0.6:  # fréquence accrue pour tests
                attack = {
                    "source_ip": random.choice(REAL_WORLD_IPS),
                    "attack_type": random.choice(ATTACK_TYPES),
                    "confidence": round(random.uniform(0.96, 1.0), 2),  # forcer haute confiance
                    "api_key": api_key
                }
                print(f"🛑 [Background] Attack '{attack['attack_type']}' from {attack['source_ip']} reported (Confidence: {attack['confidence']:.0%}).")

                try:
                    requests.post(f"{API_URL}/api/attacks/report", json=attack, timeout=5)
                except Exception as e:
                    print(f"⚠️ Failed to report attack: {e}")

                # 4. Déclencher prévention si activée et confiance > 0.95
                if prevention_enabled and attack['confidence'] > 0.95:
                    run_prevention_action(attack["source_ip"], attack["attack_type"])

            # 5. Attendre avant le prochain cycle
            time.sleep(15)

        except Exception as e:
            print(f"⚠️ Error in background task loop: {e}")
            time.sleep(15)  # éviter boucle infinie en cas d'erreur




def generate_local_data(num_samples=2000):
    """Génère des données semi-réalistes avec des signatures d'attaques."""
    print(f"Generating {num_samples} semi-realistic local data samples...")
    
    signatures = {
        'Normal': (0, 0.0, 0.1), 'Port_Scanning': (1, 0.8, 1.0),
        'DDoS_TCP': (2, 0.9, 1.0), 'DDoS_UDP': (2, 0.9, 1.0), 'DDoS_HTTP': (2, 0.9, 1.0),
        'SQL_Injection': (3, 0.7, 0.9), 'XSS': (3, 0.7, 0.9),
        'Backdoor': (4, 0.8, 0.95), 'Password': (5, 0.9, 1.0),
        'Uploading': (6, 0.8, 1.0), 'Ransomware': (0, 0.9, 1.0),
    }
    
    X_raw, y_raw = [], []
    for _ in range(num_samples):
        attack_type = random.choice(ATTACK_LABELS)
        label_index = ATTACK_LABELS.index(attack_type)
        
        features = np.random.rand(NUM_FEATURES) * 0.1
        
        if attack_type in signatures:
            idx, min_val, max_val = signatures[attack_type]
            features[idx] = random.uniform(min_val, max_val)
            
        X_raw.append(features)
        y_raw.append(label_index)

    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:(i + TIME_STEPS)])
        ys.append(y_raw[i + TIME_STEPS])
        
    if not Xs: return None
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
            self.model.compile(
                optimizer="adam",
                loss="sparse_categorical_crossentropy",
                metrics=["accuracy"]
            )
            self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=1)
            print("✅ Local training round finished.")
            return self.model.get_weights(), len(self.x_train), {}
        except Exception as e:
            print(f"❌ Error in fit(): {e}")
            return self.model.get_weights(), 0, {}

    def evaluate(self, parameters, config):
        try:
            self.model.set_weights(parameters)
            self.model.compile(
                optimizer="adam",
                loss="sparse_categorical_crossentropy",
                metrics=["accuracy"]
            )
            loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
            print(f"📊 Evaluation result — Loss: {loss:.4f}, Accuracy: {accuracy:.4f}")
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

    # Démarrer les tâches de fond (heartbeat + simulation d'attaque)
    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_tasks, args=(api_key, stop_event), daemon=True)
    bg_thread.start()
    print("✅ Background tasks (heartbeat, attack simulation) started.")

    # Générer les données locales
    data = generate_local_data()
    if not data:
        print("❌ Data generation failed. Exiting.")
        stop_event.set()
        return
    x_train, x_val, y_train, y_val = data
    print(f"✅ Data generated: x_train={x_train.shape}, y_train={y_train.shape}, x_val={x_val.shape}, y_val={y_val.shape}")

    # Créer le modèle
    try:
        print("Creating model architecture from definition...")
        model = create_model()
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        print(model.summary())
        print("✅ Model created and compiled.")
    except Exception as e:
        print(f"❌ Failed to create model: {e}")
        stop_event.set()
        bg_thread.join(1)
        return

    # Enregistrement auprès du backend (sans flower_cid)
    try:
        payload = {"api_key": api_key}
        response = requests.post(f"{API_URL}/api/fl/register", json=payload, timeout=5)
        if response.status_code == 200:
            print(f"✅ Client registered successfully with backend.")
        else:
            print(f"⚠️ Failed to register client. Status: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Could not register client with backend. Error: {e}")

    # Créer le client Flower
    client = CnnLstmClient(model, x_train, y_train, x_val, y_val)
    print(f"Connecting to Flower server at {FLOWER_SERVER_ADDRESS}...")

    try:
        fl.client.start_numpy_client(
            server_address=FLOWER_SERVER_ADDRESS,
            client=client
        )
    except Exception as e:
        print(f"❌ Could not connect to Flower server: {e}")
    finally:
        print("Shutting down background tasks...")
        stop_event.set()
        bg_thread.join(2)


if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    main()