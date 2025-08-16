import streamlit as st
import pandas as pd
import requests
import os
import time
import hashlib
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier
from catboost import CatBoostClassifier  # 🔥 tambahan CatBoost

# ==== CONFIG ====
MOBSF_URL = "https://a451a55e5904.ngrok-free.app"
MOBSF_API_KEY = "32a80594bfcab9678c087be240c5d103d5a0bfb81ee60e6e886b81a090119a3b"
VT_API_KEY = "2a5e4a34ab856cae72d93d306df7b4f2b9521c66192b9f2ad5132b3b988c52d7"

MOBSF_HEADERS = {"Authorization": MOBSF_API_KEY}
DATASET_PATH = "data.csv"
LABEL_COLUMN = "Result"

# ==== LOAD DATASET & TRAIN MODELS ====
dataset = pd.read_csv(DATASET_PATH)
all_permissions = dataset.columns[:-1].tolist()

X = dataset[all_permissions]
y = dataset[LABEL_COLUMN]

# RandomForest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X, y)

# CatBoost (silent training agar tidak spam di terminal)
cat_model = CatBoostClassifier(iterations=200, depth=6, learning_rate=0.1, random_state=42, verbose=0)
cat_model.fit(X, y)

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
st.markdown("Upload one or multiple APKs to analyze them with **MobSF**, **VirusTotal**, and compare ML models (RandomForest & CatBoost).")

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
                binary_permissions = ["1" if perm in used_permissions else "0" for perm in all_permissions]

                # RandomForest prediction
                rf_pred = rf_model.predict([binary_permissions])[0]
                rf_proba = rf_model.predict_proba([binary_permissions])[0]

                # CatBoost prediction
                cat_pred = cat_model.predict([binary_permissions])[0]
                cat_proba = cat_model.predict_proba([binary_permissions])[0]

                # Bagging (base = RandomForest default) 
                bagging_model = BaggingClassifier(n_estimators=50, random_state=42) bagging_model.fit(X, y)

                # tampilkan hasil keduanya dalam tabel
                pred_df = pd.DataFrame({
                    "Model": ["RandomForest", "CatBoost","Bagging"],
                    "Prediction": ["🛑 MALWARE" if rf_pred == 1 else "✅ BENIGN",
                                   "🛑 MALWARE" if cat_pred == 1 else "✅ BENIGN"],
                    "Benign %": [rf_proba[0]*100, cat_proba[0]*100],
                    "Malware %": [rf_proba[1]*100, cat_proba[1]*100]
                })
                st.table(pred_df)

                # permissions
                perm_df = pd.DataFrame({
                    "Permission": all_permissions,
                    "Used": ["Yes" if bit == "1" else "No" for bit in binary_permissions]
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
                        color = "red"
                        icon = "🚨"
                        text = f"{malicious}/{total} vendors flagged this file as malicious"
                        st.markdown(f"<h3 style='color:{color};'>{icon} {text}</h3>", unsafe_allow_html=True)
                        st.markdown("<h1 style='text-align: center; color:red;'>🚨 This APK File is MALICIOUS</h1>", unsafe_allow_html=True)
                    else:
                        color = "green"
                        icon = "✅"
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

