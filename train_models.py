import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier
from catboost import CatBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
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

# ==== TRAIN MODELS ====
rf_model  = RandomForestClassifier(n_estimators=100, random_state=42).fit(X, y)
cat_model = CatBoostClassifier(iterations=200, depth=6, learning_rate=0.1, random_state=42, verbose=0).fit(X, y)
lr_model  = LogisticRegression(max_iter=500, random_state=42).fit(X, y)
dt_model  = DecisionTreeClassifier(max_depth=10, random_state=42).fit(X, y)
nb_model  = GaussianNB().fit(X, y)
mlp_model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=42).fit(X, y)
lgb_model = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.1, random_state=42).fit(X, y)
bag_model = BaggingClassifier(n_estimators=100, random_state=42).fit(X, y)

# ==== SAVE MODELS ====
joblib.dump(rf_model,  "models/rf_model.pkl")
joblib.dump(cat_model, "models/cat_model.pkl")
joblib.dump(lr_model,  "models/lr_model.pkl")
joblib.dump(dt_model,  "models/dt_model.pkl")
joblib.dump(nb_model,  "models/nb_model.pkl")
joblib.dump(mlp_model, "models/mlp_model.pkl")
joblib.dump(lgb_model, "models/lgb_model.pkl")
joblib.dump(bag_model, "models/bag_model.pkl")

print("✅ Semua model berhasil dilatih & disimpan ke folder models/")
