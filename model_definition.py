# model_definition.py (Version Finale Optimisée)
import tensorflow as tf

ATTACK_LABELS = sorted([...]) # Votre liste complète d'attaques
NUM_CLASSES = len(ATTACK_LABELS)

def create_model(time_steps=20, num_features=7):
    model = tf.keras.Sequential([
        tf.keras.layers.Conv1D(128, 3, activation='relu', padding='same', input_shape=(time_steps, num_features)),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.MaxPooling1D(2),
        tf.keras.layers.Dropout(0.3),

        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(128, return_sequences=True)),
        tf.keras.layers.Bidirectional(tf.keras.layers.LSTM(64)),
        
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dropout(0.4),
        tf.keras.layers.Dense(NUM_CLASSES, activation='softmax')
    ])
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=3e-4),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    return model