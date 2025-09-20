import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier, ExtraTreesClassifier
from catboost import CatBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
import lightgbm as lgb
import xgboost as xgb

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
rf_model  = RandomForestClassifier(n_estimators=100, random_state=42).fit(X_train, y_train)
bag_model = BaggingClassifier(n_estimators=200, random_state=42).fit(X_train, y_train)
et_model  = ExtraTreesClassifier(n_estimators=300, random_state=42).fit(X_train, y_train)
cat_model = CatBoostClassifier(iterations=2000, depth=6, learning_rate=0.1, random_state=42, verbose=0).fit(X_train, y_train)
lgb_model = lgb.LGBMClassifier(n_estimators=300, learning_rate=0.1, random_state=42).fit(X_train, y_train)
dt_model  = DecisionTreeClassifier(max_depth=30, random_state=42).fit(X_train, y_train)
mlp_model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=1000, random_state=42).fit(X_train, y_train)
lr_model  = LogisticRegression(max_iter=500, random_state=42).fit(X_train, y_train)
knn_model = KNeighborsClassifier(n_neighbors=10).fit(X_train, y_train)
xg_model  = xgb.XGBClassifier(n_estimators=1000, learning_rate=0.1, random_state=42).fit(X_train, y_train)

# ==== SAVE MODELS ==== 
joblib.dump(rf_model,  "models/rf_model.pkl")
joblib.dump(cat_model, "models/cat_model.pkl")
joblib.dump(lr_model,  "models/lr_model.pkl")
joblib.dump(dt_model,  "models/dt_model.pkl")
joblib.dump(et_model,  "models/et_model.pkl") 
joblib.dump(mlp_model, "models/mlp_model.pkl")
joblib.dump(lgb_model, "models/lgb_model.pkl")
joblib.dump(bag_model, "models/bag_model.pkl")
joblib.dump(knn_model, "models/knn_model.pkl") 
joblib.dump(xg_model, "models/xg_model.pkl")

print("✅ Semua model berhasil dilatih & disimpan ke folder models/")
