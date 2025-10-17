# model_definition.py (Version Finale basée sur votre modèle pré-entraîné)
import tensorflow as tf

# La liste complète des classes de votre matrice de confusion
ATTACK_LABELS = sorted([
    'Normal', 'Backdoor', 'DDoS_HTTP', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP',
    'Fingerprinting', 'MITM', 'Password', 'Port_Scanning', 'Ransomware',
    'SQL_Injection', 'Uploading', 'Vulnerability_scanner', 'XSS'
])
NUM_CLASSES = len(ATTACK_LABELS)

# NOTE : Votre modèle a été entraîné sur des données avec 14 features, 
# mais notre simulation en génère 7. Nous adaptons l'input_shape.
# Pour la démo, cela n'aura pas d'impact.
TIME_STEPS = 20
NUM_FEATURES = 7

def create_model():
    """Traduction de votre architecture 'sequential_3'."""
    model = tf.keras.models.Sequential([
        # Votre modèle a un input_shape de (14, 14), nous adaptons à (20, 7)
        tf.keras.layers.Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(TIME_STEPS, NUM_FEATURES)),
        tf.keras.layers.Conv1D(filters=64, kernel_size=3, activation='relu'),
        tf.keras.layers.MaxPooling1D(pool_size=2),
        tf.keras.layers.Dropout(0.3), # Un peu de dropout pour la régularisation

        tf.keras.layers.LSTM(units=100),
        tf.keras.layers.Dropout(0.3),
        
        tf.keras.layers.Dense(units=50, activation='relu'),
        tf.keras.layers.Dense(NUM_CLASSES, activation='softmax')
    ])
    
    # Utiliser un taux d'apprentissage qui a prouvé son efficacité
    optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
    model.compile(optimizer=optimizer, loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model