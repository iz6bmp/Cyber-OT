# Unlabeled - Offline Training LSTM Forecaster
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from tensorflow.keras.callbacks import EarlyStopping
import joblib

CSV_PATH = "features_dataset_normal.csv"

FEATURES = [
    "rx_packets_per_sec",
    "rx_bytes_per_sec",
    "avg_pkt_size_bytes_to_dst",
    "avg_wire_iat_ms",
]

SEQ_LEN = 20          # 20 seconds history
VAL_FRAC = 0.2        # last 20% for validation
THRESH_PCTL = 99      # 99th percentile threshold


def make_sequences(data: np.ndarray, seq_len: int):
    """Create (X_window -> y_next) pairs."""
    xs, ys = [], []
    for i in range(len(data) - seq_len):
        xs.append(data[i:i + seq_len])
        ys.append(data[i + seq_len])
    return np.asarray(xs, dtype=np.float32), np.asarray(ys, dtype=np.float32)


# ---------- 1) Load and prepare data ----------
df = pd.read_csv(CSV_PATH)

# ensure time sorted
if "time" in df.columns:
    df = df.sort_values("time")

# keep only needed columns and drop NaNs
df = df[FEATURES].dropna().reset_index(drop=True)

X_raw = df.astype("float32").values

# ---------- 2) Fit scaler on TRAIN ONLY (avoid leakage) ----------
n = len(X_raw)
if n <= SEQ_LEN + 10:
    raise ValueError(f"Not enough rows ({n}) for SEQ_LEN={SEQ_LEN}. Need more normal data.")

split_idx = int((1.0 - VAL_FRAC) * n)
# make sure validation has enough room for sequences too
split_idx = max(split_idx, SEQ_LEN + 1)

X_train_raw = X_raw[:split_idx]
X_val_raw   = X_raw[split_idx:]

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_raw)
X_val_scaled   = scaler.transform(X_val_raw)

# ---------- 3) Build sequence datasets (time-ordered) ----------
X_train_seq, y_train_seq = make_sequences(X_train_scaled, SEQ_LEN)
X_val_seq,   y_val_seq   = make_sequences(X_val_scaled, SEQ_LEN)

print("Train sequence dataset:", X_train_seq.shape, y_train_seq.shape)
print("Val sequence dataset  :", X_val_seq.shape, y_val_seq.shape)

if len(X_val_seq) < 10:
    print("⚠ Warning: validation set is very small. Consider more data or smaller VAL_FRAC.")

# ---------- 4) Build and train LSTM forecaster ----------
model = Sequential([
    LSTM(32, input_shape=(SEQ_LEN, len(FEATURES))),
    Dense(len(FEATURES))
])
model.compile(optimizer="adam", loss="mse")

es = EarlyStopping(
    monitor="val_loss",
    patience=5,
    restore_best_weights=True
)

history = model.fit(
    X_train_seq, y_train_seq,
    validation_data=(X_val_seq, y_val_seq),
    epochs=50,
    batch_size=32,
    shuffle=False,   # IMPORTANT for time series
    callbacks=[es],
    verbose=2
)

# ---------- 5) Compute anomaly threshold on VALIDATION errors ----------
y_val_pred = model.predict(X_val_seq, verbose=0)
val_mse = np.mean((y_val_pred - y_val_seq) ** 2, axis=1)

THRESHOLD = float(np.percentile(val_mse, THRESH_PCTL))

print(f"Val MSE mean={val_mse.mean():.6f}, {THRESH_PCTL}th% threshold={THRESHOLD:.6f}")

# ---------- 6) Save model + metadata ----------
model.save("lstm_forecaster.h5")
joblib.dump(
    {
        "scaler": scaler,
        "features": FEATURES,
        "seq_len": SEQ_LEN,
        "threshold": THRESHOLD,
        "threshold_percentile": THRESH_PCTL,
        "val_frac": VAL_FRAC,
    },
    "lstm_meta.joblib"
)

print("✅ Saved LSTM model to lstm_forecaster.h5 and metadata to lstm_meta.joblib")
