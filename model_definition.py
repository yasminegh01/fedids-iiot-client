# iiot_client/model_definition.py
import tensorflow as tf

def create_model(time_steps=20, num_features=7, num_classes=15):
    """Crée et compile le modèle CNN-LSTM."""
    model = tf.keras.models.Sequential([
        # On définit l'input_shape sur la première couche
        tf.keras.layers.Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(time_steps, num_features)),
        tf.keras.layers.MaxPooling1D(pool_size=2),
        tf.keras.layers.LSTM(units=50, return_sequences=True),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.LSTM(units=50),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(units=32, activation='relu'),
        tf.keras.layers.Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model