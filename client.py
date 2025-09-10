# backend/client.py
import flwr as fl
import tensorflow as tf
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import argparse, os, configparser, requests, time, threading
from typing import Optional

# Config
API_URL="http://127.0.0.1:8000"; DATA_PATH='data/balanced_edge.csv'; TIME_STEPS=20
EDGE_FEATURES=['icmp.checksum','icmp.seq_le','tcp.ack','tcp.ack_raw','mqtt.topic_0','mqtt.topic_0.0','mqtt.topic_Temperature_and_Humidity']
EDGE_LABEL='Attack_type'

# Helpers
def get_device_api_key(config_file:str)->Optional[str]:
    config=configparser.ConfigParser()
    if not os.path.exists(config_file):return None
    config.read(config_file);return config.get('device','api_key',fallback=None)

def send_heartbeat(api_key:str, stop_event:threading.Event):
    while not stop_event.is_set():
        if api_key:
            try:requests.post(f"{API_URL}/api/devices/heartbeat",json={"api_key":api_key},timeout=10);print(f"[Heartbeat] Ping sent for ...{api_key[-4:]}.")
            except:print("[Heartbeat] Could not reach backend.")
        time.sleep(90)

# Data
def create_sequences(X,y,ts=TIME_STEPS):Xs,ys=[],[];[Xs.append(X[i:(i+ts)]) or ys.append(y[i+ts]) for i in range(len(X)-ts)];return np.array(Xs),np.array(ys)
def load_and_preprocess_data(path,feats,lbl,cid,num_c):
    try:
        df=pd.read_csv(path); part=len(df)//num_c; s,e=cid*part,(cid+1)*part; df=df.iloc[s:e].copy(); df.dropna(subset=feats+[lbl],inplace=True)
        if df.empty:return None
        X_s=MinMaxScaler().fit_transform(df[feats]);y_e=LabelEncoder().fit_transform(df[lbl])
        X_q,y_q=create_sequences(X_s,y_e); return train_test_split(X_q,y_q,test_size=0.2)
    except: return None

# Flower Client
class CnnLstmClient(fl.client.NumPyClient):
    def __init__(self,model,xt,yt,xv,yv): self.model=model; self.x_train,self.y_train=xt,yt; self.x_test,self.y_test=xv,yv
    def get_parameters(self,c): return self.model.get_weights()
    def fit(self,p,c): self.model.set_weights(p);self.model.compile('adam','sparse_categorical_crossentropy',['accuracy']);self.model.fit(self.x_train,self.y_train,epochs=2,batch_size=32,verbose=0); return self.model.get_weights(),len(self.x_train),{}
    def evaluate(self,p,c):self.model.set_weights(p);self.model.compile('adam','sparse_categorical_crossentropy',['accuracy']);loss,acc=self.model.evaluate(self.x_test,self.y_test,verbose=0); return float(loss),len(self.x_test),{"accuracy":float(acc)}

# Main
def main():
    parser = argparse.ArgumentParser(description="FedIds IIoT Client")
    parser.add_argument("--client-id",type=int,required=True)
    parser.add_argument("--config",type=str,required=True,help="e.g., config_client_0.ini")
    parser.add_argument("--num-clients",type=int,default=2)
    args = parser.parse_args()

    api_key = get_device_api_key(args.config)
    if not api_key: print(f"FATAL: API Key not in {args.config}"); return

    print(f"--- Client {args.client_id} ({args.config}) ---")
    data = load_and_preprocess_data(DATA_PATH,EDGE_FEATURES,EDGE_LABEL,args.client_id,args.num_clients)
    if data is None: print("❌ Data loading failed."); return
    xt,xv,yt,yv=data
    model=tf.keras.models.load_model('model_edge.h5')
    client=CnnLstmClient(model,xt,yt,xv,yv)
    
    stop=threading.Event(); hb_thread=threading.Thread(target=send_heartbeat,args=(api_key,stop),daemon=True); hb_thread.start()
    try:fl.client.start_client(server_address="127.0.0.1:8080", client=client)

    finally: print("Shutting down..."); stop.set(); hb_thread.join(2)

if __name__ == "__main__":
    main()