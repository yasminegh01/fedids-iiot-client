# backend/model.py
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, LSTM, Dense

def create_cnn_lstm_model(input_shape, num_classes):
    model=Sequential([Conv1D(filters=64,kernel_size=3,activation='relu',input_shape=input_shape),MaxPooling1D(pool_size=2),LSTM(50,return_sequences=False),Dense(100,activation='relu'),Dense(num_classes,activation='softmax')])
    return model