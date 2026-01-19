# Offline training Random Forest Forecaster_Labeled.py
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import classification_report, confusion_matrix
import joblib

CSV_PATH = "features_dataset.csv"   # labeled: attack/normal

FEATURES = [
    "rx_packets_per_sec",
    "rx_bytes_per_sec",
    "avg_pkt_size_bytes_to_dst",
    "avg_wire_iat_ms",
]

SEQ_LEN = 20          # 20 seconds history
VAL_FRAC = 0.2        # last 20% validation (time-ordered)
THRESH_PCTL = 99      # 99th percentile threshold on NORMAL validation errors


def make_windows(data_scaled: np.ndarray, seq_len: int):
    """
    Supervised windows:
      X = flattened last seq_len observations
      y = next observation (multi-output)
    """
    X_list, y_list = [], []
    for i in range(len(data_scaled) - seq_len):
        X_list.append(data_scaled[i:i + seq_len].reshape(-1))
        y_list.append(data_scaled[i + seq_len])
    return np.asarray(X_list, dtype=np.float32), np.asarray(y_list, dtype=np.float32)


# ---------------- load ----------------
df = pd.read_csv(CSV_PATH)

# normalize label values to {0,1} but keep original column too
df["label"] = df["label"].astype(str).str.lower().str.strip()
df = df[df["label"].isin(["normal", "attack"])].copy()
df["label_bin"] = df["label"].map({"normal": 0, "attack": 1}).astype(int)

# time sort if present
if "time" in df.columns:
    df = df.sort_values("time")

# keep needed cols
df = df[["label", "label_bin"] + FEATURES].dropna().reset_index(drop=True)

# ---------------- train on NORMAL only ----------------
df_norm = df[df["label_bin"] == 0].copy()
X_raw = df_norm[FEATURES].astype("float32").values

n = len(X_raw)
if n <= SEQ_LEN + 10:
    raise ValueError(f"Not enough NORMAL rows ({n}) for SEQ_LEN={SEQ_LEN}. Need more normal data.")

# time split (normal only) to avoid leakage
split_idx = int((1.0 - VAL_FRAC) * n)
split_idx = max(split_idx, SEQ_LEN + 1)

X_train_raw = X_raw[:split_idx]
X_val_raw   = X_raw[split_idx:]

# scale on TRAIN only
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train_raw)
X_val_scaled   = scaler.transform(X_val_raw)

# build windows
X_train_win, y_train = make_windows(X_train_scaled, SEQ_LEN)
X_val_win,   y_val   = make_windows(X_val_scaled, SEQ_LEN)

print("Train windows:", X_train_win.shape, y_train.shape)
print("Val windows  :", X_val_win.shape, y_val.shape)

# ---------------- model ----------------
rf = RandomForestRegressor(
    n_estimators=400,
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train_win, y_train)

# ---------------- threshold (NORMAL validation) ----------------
y_val_pred = rf.predict(X_val_win)
val_mse = np.mean((y_val_pred - y_val) ** 2, axis=1)
threshold = float(np.percentile(val_mse, THRESH_PCTL))

print(f"Normal-Val MSE mean={val_mse.mean():.6f}, {THRESH_PCTL}th% threshold={threshold:.6f}")

# ---------------- optional evaluation on LABELED full data ----------------
# Evaluate detection by: use window -> predict next -> compare mse to threshold
# and compare predicted anomaly vs label of the "next" time step
X_all_raw = df[FEATURES].astype("float32").values
y_all_label_next = df["label_bin"].values

X_all_scaled = scaler.transform(X_all_raw)
X_all_win, y_all_next = make_windows(X_all_scaled, SEQ_LEN)

# labels for the "next step" targets (align with windows)
y_next_labels = y_all_label_next[SEQ_LEN:]  # label of i+SEQ_LEN

y_all_pred = rf.predict(X_all_win)
all_mse = np.mean((y_all_pred - y_all_next) ** 2, axis=1)
y_anom_pred = (all_mse > threshold).astype(int)

print("\n=== Forecast-error detection vs labels (for reporting only) ===")
print("Confusion matrix:\n", confusion_matrix(y_next_labels, y_anom_pred))
print(classification_report(y_next_labels, y_anom_pred, digits=4, target_names=["normal","attack"]))

# ---------------- save ----------------
joblib.dump(
    {
        "model": rf,
        "scaler": scaler,
        "features": FEATURES,
        "seq_len": SEQ_LEN,
        "threshold": threshold,
        "threshold_percentile": THRESH_PCTL,
        "val_frac": VAL_FRAC,
    },
    "rf_forecaster.joblib"
)

print("✅ Saved RF forecaster to rf_forecaster.joblib")
