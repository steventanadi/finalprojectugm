import streamlit as st
import pandas as pd
import requests
import os
import time
import hashlib
import numpy as np
import joblib

# ==== CONFIG ====
MOBSF_URL = "https://7f5d513e0b3c.ngrok-free.app"
MOBSF_API_KEY = "32a80594bfcab9678c087be240c5d103d5a0bfb81ee60e6e886b81a090119a3b"
VT_API_KEY   = "2a5e4a34ab856cae72d93d306df7b4f2b9521c66192b9f2ad5132b3b988c52d7"

MOBSF_HEADERS = {"Authorization": MOBSF_API_KEY}
DATASET_PATH  = "data.csv"
LABEL_COLUMN  = "Result"

# ==== LOAD DATASET (hanya untuk ambil daftar permission) ====
dataset = pd.read_csv(DATASET_PATH)
dataset[dataset.columns[:-1]] = dataset[dataset.columns[:-1]].astype(int)
all_permissions = dataset.columns[:-1].tolist()

# ==== LOAD MODELS ====
@st.cache_resource
def load_models():
    models = {
        "RandomForest": joblib.load("models/rf_model.pkl"),
        "CatBoost": joblib.load("models/cat_model.pkl"),
        "LogisticRegression": joblib.load("models/lr_model.pkl"),
        "DecisionTree": joblib.load("models/dt_model.pkl"),
        "NaiveBayes": joblib.load("models/nb_model.pkl"),
        "MLPClassifier": joblib.load("models/mlp_model.pkl"),
        "LightGBM": joblib.load("models/lgb_model.pkl"),
        "Bagging": joblib.load("models/bag_model.pkl"),
    }
    return models

models = load_models()

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
                binary_permissions = [1 if perm in used_permissions else 0 for perm in all_permissions]
                binary_permissions = np.array(binary_permissions).reshape(1, -1)

                # Predictions
                pred_results = []
                for name, model in models.items():
                    pred = model.predict(binary_permissions)[0]
                    prob = model.predict_proba(binary_permissions)[0]
                    pred_results.append({
                        "Model": name,
                        "Prediction": "🛑 MALWARE" if pred == 1 else "✅ BENIGN",
                        "Benign %": prob[0] * 100,
                        "Malware %": prob[1] * 100
                    })

                st.table(pd.DataFrame(pred_results))

                # Show permissions
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
                        st.markdown(f"<h3 style='color:red;'>🚨 {malicious}/{total} vendors flagged this file as malicious</h3>", unsafe_allow_html=True)
                        st.markdown("<h1 style='text-align: center; color:red;'>🚨 This APK File is MALICIOUS</h1>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<h3 style='color:green;'>✅ {malicious}/{total} vendors flagged this file as malicious</h3>", unsafe_allow_html=True)
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

            st.markdown("---")
