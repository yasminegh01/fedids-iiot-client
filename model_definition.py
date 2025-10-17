# model_definition.py
import tensorflow as tf

# --- Model definition ---
def create_model(input_shape=(24, 1), num_classes=7):
    """
    Creates a simple CNN + LSTM model for time series classification.
    
    Args:
        input_shape: Tuple, the shape of input features (timesteps, features)
        num_classes: int, number of output classes
    
    Returns:
        tf.keras.Model
    """
    model = tf.keras.Sequential([
        tf.keras.layers.Conv1D(64, 3, activation="relu", padding="same", input_shape=input_shape),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.MaxPooling1D(2),

        tf.keras.layers.Conv1D(128, 3, activation="relu", padding="same"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.MaxPooling1D(2),

        tf.keras.layers.LSTM(64, return_sequences=False, dropout=0.2),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(num_classes, activation="softmax"),
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )

    return model

NUM_CLASSES = 7
ATTACK_LABELS = [
    'Normal', 'Backdoor', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP', 'Password',
    'Port_Scanning', 'Ransomware', 'SQL_Injection', 'Spyware', 'Trojan',
    'Uploading', 'Vulnerability_Scan', 'XSS', 'MITM'
]
