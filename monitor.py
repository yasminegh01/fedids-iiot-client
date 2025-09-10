# monitor.py
import asyncio, random, json, httpx
from datetime import datetime

API_URL = "http://127.0.0.1:8000/api/attacks/report"
API_KEY = "YOUR_DEVICE_API_KEY_HERE"  # optional if your endpoint needs auth
ATTACK_TYPES = ["Backdoor", "MITM", "Port Scan", "DDoS", "Ransomware"]

# generate a public-like IP for testing
def random_ip():
    # avoid private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    return ".".join(str(random.randint(1, 223)) for _ in range(4))

async def send_attack():
    attack = {
        "source_ip": random_ip(),
        "attack_type": random.choice(ATTACK_TYPES),
        "confidence": round(random.uniform(0.7, 1.0), 2)  # 70%-100%
    }

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(API_URL, json=attack)
            if r.status_code == 200:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Logged attack: {attack['attack_type']} from {attack['source_ip']}")
            else:
                print(f"❌ Failed to log attack: {r.text}")
        except Exception as e:
            print(f"❌ Error sending attack: {e}")

async def main_loop(interval_seconds=10):
    while True:
        await send_attack()
        await asyncio.sleep(interval_seconds)

if __name__ == "__main__":
    asyncio.run(main_loop())
