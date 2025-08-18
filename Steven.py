import streamlit as st
import pandas as pd
import requests
import os
import time
import hashlib
import matplotlib.pyplot as plt
import numpy as np  

# ==== Machine Learning ====
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier
from catboost import CatBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
import lightgbm as lgb

# ==== CONFIG ====
MOBSF_URL = "https://314c741856d5.ngrok-free.app"
MOBSF_API_KEY = "32a80594bfcab9678c087be240c5d103d5a0bfb81ee60e6e886b81a090119a3b"
VT_API_KEY = "2a5e4a34ab856cae72d93d306df7b4f2b9521c66192b9f2ad5132b3b988c52d7"

MOBSF_HEADERS = {"Authorization": MOBSF_API_KEY}
DATASET_PATH = "data.csv"
LABEL_COLUMN = "Result"

# ==== LOAD DATASET & TRAIN MODELS ====
dataset = pd.read_csv(DATASET_PATH)

# pastikan semua permission adalah numerik
dataset[dataset.columns[:-1]] = dataset[dataset.columns[:-1]].astype(int)

all_permissions = dataset.columns[:-1].tolist()
X = dataset[all_permissions]
y = dataset[LABEL_COLUMN]

# RandomForest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X, y)

# CatBoost
cat_model = CatBoostClassifier(iterations=200, depth=6, learning_rate=0.1, random_state=42, verbose=0)
cat_model.fit(X, y)

# Logistic Regression
lr_model = LogisticRegression(max_iter=500, random_state=42)
lr_model.fit(X, y)

# Decision Tree
dt_model = DecisionTreeClassifier(max_depth=10, random_state=42)
dt_model.fit(X, y)

# Naive Bayes
nb_model = GaussianNB()
nb_model.fit(X, y)

# MLP Classifier (Neural Network)
mlp_model = MLPClassifier(hidden_layer_sizes=(100,), max_iter=500, random_state=42)
mlp_model.fit(X, y)

# LightGBM
lgb_model = lgb.LGBMClassifier(n_estimators=200, learning_rate=0.1, max_depth=-1, random_state=42)
lgb_model.fit(X, y)

# Bagging
bag_model = BaggingClassifier(n_estimators=100, random_state=42)
bag_model.fit(X, y)

# ==== Fungsi utilitas ====
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ==== STREAMLIT UI ====
st.set_page_config(page_title="APK Analysis (MobSF + VirusTotal)", layout="wide")
st.title("🔍 APK Malware Analysis")
st.markdown("Upload one or multiple APKs to analyze them with **MobSF**, **VirusTotal**, and compare ML models.")

uploaded_files = st.file_uploader("Upload APK file(s)", type=["apk"], accept_multiple_files=True)

if uploaded_files:
    for uploaded_file in uploaded_files:
        with st.container():
            st.markdown(f"## 📂 File: **{uploaded_file.name}**")

            # save file
            apk_path = f"temp_{uploaded_file.name}"
            with open(apk_path, "wb") as f:
                f.write(uploaded_file.read())
            st.success(f"File uploaded: {uploaded_file.name}")

            # ========== MOBSF ==========
            st.subheader("📊 MobSF + ML Prediction")
            try:
                resp_upload = requests.post(
                    f"{MOBSF_URL}/api/v1/upload",
                    headers=MOBSF_HEADERS,
                    files={"file": (os.path.basename(apk_path), open(apk_path, "rb"), "application/vnd.android.package-archive")},
                    verify=False
                )
                resp_upload.raise_for_status()
                apk_hash = resp_upload.json()["hash"]

                requests.post(f"{MOBSF_URL}/api/v1/scan", headers=MOBSF_HEADERS, data={"hash": apk_hash}, verify=False)
                time.sleep(5)

                resp_json = requests.post(
                    f"{MOBSF_URL}/api/v1/report_json",
                    headers=MOBSF_HEADERS,
                    data={"hash": apk_hash},
                    verify=False
                )
                resp_json.raise_for_status()
                report = resp_json.json()

                used_permissions = list(report.get("permissions", {}).keys())

                # gunakan int (0/1), bukan string
                binary_permissions = [1 if perm in used_permissions else 0 for perm in all_permissions]
                binary_permissions = np.array(binary_permissions).reshape(1, -1)

                # Predictions dari semua model
                models = {
                    "RandomForest": (rf_model, rf_model.predict(binary_permissions)[0], rf_model.predict_proba(binary_permissions)[0]),
                    "CatBoost": (cat_model, cat_model.predict(binary_permissions)[0], cat_model.predict_proba(binary_permissions)[0]),
                    "LogisticRegression": (lr_model, lr_model.predict(binary_permissions)[0], lr_model.predict_proba(binary_permissions)[0]),
                    "DecisionTree": (dt_model, dt_model.predict(binary_permissions)[0], dt_model.predict_proba(binary_permissions)[0]),
                    "NaiveBayes": (nb_model, nb_model.predict(binary_permissions)[0], nb_model.predict_proba(binary_permissions)[0]),
                    "MLPClassifier": (mlp_model, mlp_model.predict(binary_permissions)[0], mlp_model.predict_proba(binary_permissions)[0]),
                    "LightGBM": (lgb_model, lgb_model.predict(binary_permissions)[0], lgb_model.predict_proba(binary_permissions)[0]),
                    "Bagging": (bag_model, bag_model.predict(binary_permissions)[0], bag_model.predict_proba(binary_permissions)[0])
                }

                pred_df = pd.DataFrame({
                    "Model": list(models.keys()),
                    "Prediction": ["🛑 MALWARE" if m[1] == 1 else "✅ BENIGN" for m in models.values()],
                    "Benign %": [m[2][0]*100 for m in models.values()],
                    "Malware %": [m[2][1]*100 for m in models.values()]
                })
                st.table(pred_df)

                # permissions
                perm_df = pd.DataFrame({
                    "Permission": all_permissions,
                    "Used": ["Yes" if bit == 1 else "No" for bit in binary_permissions.flatten()]
                })
                st.dataframe(perm_df)

            except Exception as e:
                st.error(f"MobSF Error: {e}")

            # ========== VIRUSTOTAL ==========
            st.subheader("🧪 VirusTotal Analysis")
            try:
                file_hash = file_sha256(apk_path)
                headers = {"x-apikey": VT_API_KEY}
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                resp = requests.get(url, headers=headers)

                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]
                    stats = data["last_analysis_stats"]

                    st.write("**File Hash (SHA256):**", file_hash)

                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())

                    if malicious > 0:
                        color = "red"; icon = "🚨"
                        text = f"{malicious}/{total} vendors flagged this file as malicious"
                        st.markdown(f"<h3 style='color:{color};'>{icon} {text}</h3>", unsafe_allow_html=True)
                        st.markdown("<h1 style='text-align: center; color:red;'>🚨 This APK File is MALICIOUS</h1>", unsafe_allow_html=True)
                    else:
                        color = "green"; icon = "✅"
                        text = f"{malicious}/{total} vendors flagged this file as malicious"
                        st.markdown(f"<h3 style='color:{color};'>{icon} {text}</h3>", unsafe_allow_html=True)
                        st.markdown("<h1 style='text-align: center; color:green;'>✅ This APK File is BENIGN</h1>", unsafe_allow_html=True)

                    av_results = data["last_analysis_results"]
                    results_list = []
                    for av, res in av_results.items():
                        results_list.append({
                            "Engine": av,
                            "Category": res["category"],
                            "Result": res["result"]
                        })
                    st.dataframe(pd.DataFrame(results_list).head(40))

                else:
                    st.warning("File not found in VirusTotal database. Upload manually on VT site.")

            except Exception as e:
                st.error(f"VirusTotal Error: {e}")

            st.markdown("---")  # pemisah antar file



