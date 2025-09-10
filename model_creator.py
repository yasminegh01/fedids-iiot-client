# backend/model_creator.py
import tensorflow as tf
import pandas as pd
from model import create_cnn_lstm_model

DATA_PATH='data/balanced_edge.csv';TIME_STEPS=20;EDGE_FEATURES=['icmp.checksum','icmp.seq_le','tcp.ack','tcp.ack_raw','mqtt.topic_0','mqtt.topic_0.0','mqtt.topic_Temperature_and_Humidity'];EDGE_LABEL='Attack_type';NUM_FEATURES=len(EDGE_FEATURES)

def main():
    print("--- Creating Initial Model ---")
    try:df=pd.read_csv(DATA_PATH);df.dropna(subset=[EDGE_LABEL],inplace=True);num_classes=df[EDGE_LABEL].nunique();print(f"✅ Found {num_classes} classes.")
    except Exception as e:print(f"❌ Error reading dataset: {e}");return
    input_shape=(TIME_STEPS,NUM_FEATURES);print(f"✅ Model Input Shape: {input_shape}")
    model=create_cnn_lstm_model(input_shape=input_shape,num_classes=num_classes)
    model.compile(optimizer='adam',loss='sparse_categorical_crossentropy',metrics=['accuracy']);model.summary()
    try:model.save('global_model.h5');model.save('model_edge.h5');print("\n✅ Successfully saved 'global_model.h5' and 'model_edge.h5'")
    except Exception as e:print(f"\n❌ Error saving model files: {e}")

if __name__=='__main__':main()