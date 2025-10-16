# model_definition.py (Version Finale avec votre architecture)
import tensorflow as tf

# La liste complète et unifiée des attaques
ATTACK_LABELS = sorted(list(set([
    'Normal', 'Backdoor', 'DDoS_HTTP', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP',
    'Fingerprinting', 'MITM', 'Password', 'Port_Scanning', 'Ransomware',
    'SQL_Injection', 'Uploading', 'Vulnerability_scanner', 'XSS'
])))
NUM_CLASSES = len(ATTACK_LABELS)

def create_model(time_steps=20, num_features=7):
    """Modèle CNN-BiLSTM amélioré avec régularisation et normalisation."""
    model = tf.keras.models.Sequential([
        tf.keras.layers.Conv1D(filters=128, kernel_size=3, activation='relu', padding='same', input_shape=(time_steps, num_features)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.MaxPooling1D(pool_size=2),
        tf.keras.layers.Dropout(0.3),

        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(64, return_sequences=True)),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(32)),

        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.4),

        tf.keras.layers.Dense(NUM_CLASSES, activation='softmax')
    ])

    # Utiliser un taux d'apprentissage plus faible pour un entraînement plus stable
    optimizer = tf.keras.optimizers.Adam(learning_rate=1e-4)
    model.compile(optimizer=optimizer, loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model