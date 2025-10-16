# backend/model_creator.py
import os
from model_definition import create_model

def main():
    print("--- Creating Initial Global Model Weights ---")
    model = create_model()
    model.summary()
    model.save_weights("global_model.weights.h5")
    print("\n✅ Successfully saved 'global_model.weights.h5'.")

if __name__ == '__main__':
    main()