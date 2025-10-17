# model_definition.py (Version Corrigée et Unifiée)
import tensorflow as tf

# On définit les constantes ici, une seule fois.
TIME_STEPS = 20
NUM_FEATURES = 7
ATTACK_LABELS = sorted([
    'Normal', 'Backdoor', 'DDoS_HTTP', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP',
    'Fingerprinting', 'MITM', 'Password', 'Port_Scanning', 'Ransomware',
    'SQL_Injection', 'Uploading', 'Vulnerability_scanner', 'XSS'
])
NUM_CLASSES = len(ATTACK_LABELS)

def create_model():
    """Crée le modèle en utilisant les constantes globales."""
    model = tf.keras.models.Sequential([
        tf.keras.layers.Conv1D(64, 3, activation="relu", padding="same", input_shape=(TIME_STEPS, NUM_FEATURES)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.MaxPooling1D(2),
        tf.keras.layers.LSTM(64, return_sequences=False, dropout=0.2),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(NUM_CLASSES, activation="softmax"),
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model