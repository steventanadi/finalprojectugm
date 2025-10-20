import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.model_selection import train_test_split
import lightgbm as lgb

# ==== CONFIG ==== 
DATASET_PATH = "data.csv"   # pastikan file dataset kamu formatnya CSV
LABEL_COLUMN = "Result"

# Buat folder "models" kalau belum ada
os.makedirs("models", exist_ok=True)

# ==== LOAD DATASET ==== 
dataset = pd.read_csv(DATASET_PATH)
dataset[dataset.columns[:-1]] = dataset[dataset.columns[:-1]].astype(int)

all_permissions = dataset.columns[:-1].tolist()
X = dataset[all_permissions]
y = dataset[LABEL_COLUMN]

# Split data into train+validation (80%) and test set (20%)
X_train_val, X_test, y_train_val, y_test = train_test_split(X, y, test_size=0.1, random_state=42)

# Split train+validation into train (70%) and validation (10%)
X_train, X_val, y_train, y_val = train_test_split(X_train_val, y_train_val, test_size=0.125, random_state=42)  # 0.125 of 0.8 is 0.1

# ==== TRAIN MODELS ==== 
rf_model = RandomForestClassifier(
    n_estimators=100, criterion='entropy', max_depth=None,
    min_samples_split=2, min_samples_leaf=1, min_weight_fraction_leaf=0.0,
    max_features='sqrt', max_leaf_nodes=None, min_impurity_decrease=0.0,
    bootstrap=True, n_jobs=-1, random_state=42, class_weight='balanced',
    ccp_alpha=0.0, max_samples=None
)
lgb_model = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.1, random_state=42)
et_model = ExtraTreesClassifier(n_estimators=200, max_depth=25, max_features='log2', bootstrap=False, n_jobs=-1, random_state=42)

# ==== SAVE MODELS ==== 
joblib.dump(rf_model,  "models/rf_model.pkl")
joblib.dump(lgb_model, "models/lgb_model.pkl")
joblib.dump(et_model,  "models/et_model.pkl")

print("✅ Semua model berhasil dilatih & disimpan ke folder models/")
