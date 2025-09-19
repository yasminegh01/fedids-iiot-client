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
REAL_WORLD_IPS = ["8.8.8.8", "1.1.1.1", "195.8.215.68", "139.130.4.5", "202.12.27.33"]
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

    def fit(self, parameters, config):
        self.model.set_weights(parameters)
        # On re-compile le modèle à chaque fit pour réinitialiser l'état de l'optimiseur
        self.model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
        self.model.fit(self.x_train, self.y_train, epochs=2, batch_size=32, verbose=0)
        print("✅ Local training round finished.")
        return self.model.get_weights(), len(self.x_train), {}

    def evaluate(self, parameters, config):
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