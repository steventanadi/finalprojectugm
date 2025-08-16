import streamlit as st
import pandas as pd
import requests
import os
import time
import hashlib
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier

# ==== CONFIG ====
MOBSF_URL = "https://a451a55e5904.ngrok-free.app"   # ganti dengan ngrok/local URL kamu
MOBSF_API_KEY = "32a80594bfcab9678c087be240c5d103d5a0bfb81ee60e6e886b81a090119a3b"
VT_API_KEY = "2a5e4a34ab856cae72d93d306df7b4f2b9521c66192b9f2ad5132b3b988c52d7"

MOBSF_HEADERS = {"Authorization": MOBSF_API_KEY}

DATASET_PATH = "data.csv"   # dataset harus ada di folder yang sama
LABEL_COLUMN = "Result"

# ==== LOAD DATASET & TRAIN MODEL ====
dataset = pd.read_csv(DATASET_PATH)
all_permissions = dataset.columns[:-1].tolist()

X = dataset[all_permissions]
y = dataset[LABEL_COLUMN]
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# ==== STREAMLIT UI ====
st.set_page_config(page_title="APK Analysis (MobSF + VirusTotal)", layout="wide")
st.title("🔍 APK Malware Analysis")
st.markdown("Upload an APK to analyze it with **MobSF** and **VirusTotal**")

uploaded_file = st.file_uploader("Upload APK file", type=["apk"])

if uploaded_file is not None:
    # save file
    apk_path = f"temp.apk"
    with open(apk_path, "wb") as f:
        f.write(uploaded_file.read())
    st.success(f"File uploaded: {uploaded_file.name}")

    # ========== MOBSF ==========
    st.subheader("📊 MobSF Analysis")
    try:
        # upload
        resp_upload = requests.post(
            f"{MOBSF_URL}/api/v1/upload",
            headers=MOBSF_HEADERS,
            files={"file": (os.path.basename(apk_path), open(apk_path, "rb"), "application/vnd.android.package-archive")},
            verify=False
        )
        resp_upload.raise_for_status()
        apk_hash = resp_upload.json()["hash"]

        # scan
        requests.post(f"{MOBSF_URL}/api/v1/scan", headers=MOBSF_HEADERS, data={"hash": apk_hash}, verify=False)
        time.sleep(5)

        # get report
        resp_json = requests.post(
            f"{MOBSF_URL}/api/v1/report_json",
            headers=MOBSF_HEADERS,
            data={"hash": apk_hash},
            verify=False
        )
        resp_json.raise_for_status()
        report = resp_json.json()

        # extract permissions
        used_permissions = list(report.get("permissions", {}).keys())
        binary_permissions = ["1" if perm in used_permissions else "0" for perm in all_permissions]

        # predict
        pred = model.predict([binary_permissions])[0]
        proba = model.predict_proba([binary_permissions])[0]

        st.write("**Prediction:**", "🛑 MALWARE" if pred == 1 else "✅ BENIGN")
        st.write(f"Confidence → Benign: {proba[0]*100:.2f}% | Malware: {proba[1]*100:.2f}%")

        # show permissions table
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
        # calculate SHA256 hash
        def file_sha256(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()

        file_hash = file_sha256(apk_path)

        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        resp = requests.get(url, headers=headers)

        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data["last_analysis_stats"]

            st.write("**File Hash (SHA256):**", file_hash)

            # --- Circle chart for detection ratio ---
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            fig, ax = plt.subplots(figsize=(0.8, 0.8))  # lebih kecil

            wedges, texts = ax.pie(
                [malicious, total - malicious],
                colors=["red", "lightgrey"],
                startangle=90,
                counterclock=False,
                wedgeprops={"width": 0.3, "edgecolor": "white"}
            )

            # --- Tulisan dinamis di bawah donut ---
            if malicious > 0:
                color = "red"
                icon = "🚨"
                text = f"{malicious}/{total} security vendors flagged this file as malicious"
            else:
                color = "green"
                icon = "✅"
                text = f"{malicious}/{total} security vendors flagged this file as malicious"

            st.markdown(
                f"<span style='color:{color}; font-weight:bold;'>{icon} {text}</span>",
                unsafe_allow_html=True
            )

            # Show AV engine results
            av_results = data["last_analysis_results"]
            results_list = []
            for av, res in av_results.items():
                results_list.append({
                    "Engine": av,
                    "Category": res["category"],
                    "Result": res["result"]
                })
            st.dataframe(pd.DataFrame(results_list).head(20))  # show top 20
        else:
            st.warning("File not found in VirusTotal database. You may need to upload it manually.")

    except Exception as e:
        st.error(f"VirusTotal Error: {e}")
