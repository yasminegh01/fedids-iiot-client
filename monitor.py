# iiot_client/monitor.py (VERSION AVEC SIMULATION GÉOGRAPHIQUE)

import requests
import time
import random
import configparser
import os
import simpleaudio as sa # Pour l'alarme sonore

API_URL = "http://192.168.1.12:8000" # <<< METTEZ VOTRE IP ICI
ATTACK_TYPES = ['Backdoor','DDoS_ICMP','DDoS_TCP','MITM','Port_Scanning','Ransomware']

# === LA NOUVELLE LOGIQUE EST ICI ===
# Une liste d'adresses IP publiques réelles et variées
# (Google DNS, Cloudflare DNS, serveurs de FAI connus, etc.)
# Nous savons que ces IP sont dans la base de données GeoLite2.
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


def get_device_api_key():
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config.get('device', 'api_key', fallback=None)


class Monitor:
    def __init__(self, api_key):
        self.api_key = api_key
        self.prevention_enabled = False
        self.last_settings_check = 0

    def check_settings(self):
        if not self.api_key or (time.time() - self.last_settings_check < 60): return
        print("\n[Monitor] Checking for new prevention settings...")
        self.last_settings_check = time.time()
        try:
            r = requests.get(f"{API_URL}/api/devices/{self.api_key}/settings", timeout=5)
            if r.status_code == 200:
                new_status = r.json().get("prevention_enabled", False)
                if new_status != self.prevention_enabled:
                    self.prevention_enabled = new_status
                    print(f"  > ✅ Prevention Status is now: {'ENABLED' if self.prevention_enabled else 'DISABLED'}")
        except: print("  > ⚠️ Warning: Could not fetch settings from backend.")

    def run_prevention_action(self, ip: str, attack: str):
        print(f"   🔥 PREMIUM PREVENTION ACTION on {ip} 🔥")
        # ... (votre logique ntfy.sh ici)
        try:
            wave_obj = sa.WaveObject.from_wave_file("siren_alarm.wav")
            wave_obj.play()
            print("      - ACTION: Sound alarm triggered on device.")
        except Exception: pass

    def loop(self):
        print("\n--- Monitoring network traffic (Simulated)... ---")
        while True:
            try:
                self.check_settings() # <<< ON ACTIVE CETTE LIGNE
                
                if random.random() > 0.6:
                    attack_type = random.choice(ATTACK_TYPES)
                    confidence = round(random.uniform(0.85, 1.0), 2)
                    source_ip = random.choice(REAL_WORLD_IPS)
                    
                    print(f"🛑 ATTACK DETECTED: '{attack_type}' from {source_ip} (Confidence: {confidence:.0%})")
                    
                    # Si la prévention est active ET que la confiance est très élevée
                    if self.prevention_enabled and confidence > 0.95:
                        self.run_prevention_action(source_ip, attack_type)
                    
                    requests.post(f"{API_URL}/api/attacks/report", json={...})
                
                time.sleep(random.randint(8, 15)) # On ralentit un peu les attaques
            except KeyboardInterrupt: break
        print("\nMonitor shut down.")

def main():
    api_key = get_device_api_key()
    if not api_key:
        print("API Key not found in config.ini")
        return
    Monitor(api_key).loop()

if __name__ == "__main__":
    main()