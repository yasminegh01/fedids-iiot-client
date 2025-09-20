# iiot_client/client.py

import flwr as fl
import tensorflow as tf
import numpy as np
import argparse, os, configparser, requests, time, threading, random # <<< 'random' EST MAINTENANT IMPORTÉ
from typing import Optional
from sklearn.model_selection import train_test_split
from model_definition import create_model 

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
ATTACK_TYPES = ['Backdoor','DDoS_ICMP','DDoS_TCP','MITM','Port_Scanning','Ransomware']

# --- Fonctions Utilitaires ---
def get_device_api_key(config_file: str) -> Optional[str]:
    config = configparser.ConfigParser(); config.read(config_file)
    return config.get('device', 'api_key', fallback=None)

def background_tasks(api_key: str, stop_event: threading.Event):
    """Thread pour le heartbeat et la simulation d'attaques."""
    while not stop_event.is_set():
        # Heartbeat
        try:
            requests.post(f"{API_URL}/api/devices/heartbeat", json={"api_key": api_key}, timeout=5)
            print(f"[Background] Heartbeat sent for ...{api_key[-4:]}.")
        except: pass

        # Simulation d'attaque (30% de chance)
        if random.random() > 0.7:
            attack = {
                "source_ip": random.choice(REAL_WORLD_IPS),
                "attack_type": random.choice(ATTACK_TYPES),
                "confidence": round(random.uniform(0.8, 1.0), 2)
            }
            try:
                requests.post(f"{API_URL}/api/attacks/report", json=attack, timeout=5)
                print(f"🛑 [Background] Attack '{attack['attack_type']}' from {attack['source_ip']} reported.")
            except: pass
        
        time.sleep(30) # Exécute les tâches toutes les 30 secondes

def generate_local_data(num_samples=1000):
    print(f"Generating {num_samples} local data samples for training...")
    X_raw = np.random.rand(num_samples, NUM_FEATURES)
    y_raw = np.random.randint(0, NUM_CLASSES, size=num_samples)
    Xs, ys = [], []
    for i in range(len(X_raw) - TIME_STEPS):
        Xs.append(X_raw[i:(i + TIME_STEPS)])
        ys.append(y_raw[i + TIME_STEPS])
    if not Xs: return None
    X_seq, y_seq = np.array(Xs), np.array(ys)
    return train_test_split(X_seq, y_seq, test_size=0.2, random_state=42)

# --- Client Flower ---
class CnnLstmClient(fl.client.NumPyClient):
    # === LA CORRECTION EST ICI ===
    # On s'assure que le constructeur __init__ est bien défini
    # et qu'il accepte tous les arguments nécessaires.
    def __init__(self, model, x_train, y_train, x_val, y_val):
        self.model = model
        self.x_train, self.y_train = x_train, y_train
        self.x_val, self.y_val = x_val, y_val

    def get_parameters(self, config):
        return self.model.get_weights()

   # === LA CORRECTION EST ICI ===
    def fit(self, parameters, config): # On ajoute 'config'
        self.model.set_weights(parameters)
        self.model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
        self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=0)
        print("✅ Local training round finished.")
        return self.model.get_weights(), len(self.x_train), {}

    # === ET ICI AUSSI ===
    def evaluate(self, parameters, config): # On ajoute 'config'
        self.model.set_weights(parameters)
        self.model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
        loss, accuracy = self.model.evaluate(self.x_val, self.y_val, verbose=0)
        return float(loss), len(self.x_val), {"accuracy": float(accuracy)}
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

    # Démarrer le thread d'arrière-plan pour le heartbeat et les alertes
    stop_event = threading.Event()
    bg_thread = threading.Thread(target=background_tasks, args=(api_key, stop_event), daemon=True)
    bg_thread.start()
    print("✅ Background tasks (heartbeat, attack simulation) started.")

    # Générer les données d'entraînement locales
    data = generate_local_data()
    if not data:
        print("❌ Data generation failed. Exiting.")
        return
    x_train, x_val, y_train, y_val = data
    
    # === LA CORRECTION EST ICI ===
    try:
        # 1. On crée une instance vide du modèle à partir du code partagé
        print("Creating model architecture from definition...")
        model = create_model() # Assurez-vous que `from model_definition import create_model` est en haut du fichier
        
        # 2. On charge UNIQUEMENT les poids dans cette structure
        print("Loading weights into model...")
        model.load_weights('global_model.weights.h5')
    
        print("✅ Model created and weights loaded successfully.")
    except Exception as e:
        print(f"❌ Failed to create/load model: {e}")
        # Arrêter le thread d'arrière-plan avant de quitter
        stop_event.set()
        bg_thread.join(1)
        return
    # === FIN DE LA CORRECTION ===

    # Démarrer le client Flower (qui est bloquant)
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