import subprocess
import os
import xml.etree.ElementTree as ET
import numpy as np
from joblib import load  # To load the trained models
import pandas as pd

# Path to APKTool and APK file
apk_path = r"SampleFile\2e0d0ae7aa05bacc4b4e6b688578410470d8296e6410922497df23e314dd2021"
output_dir = r"decompiled_output"

# List of features to search for
features = [
    "SEND_SMS",
    "INTERNET",
    "WRITE_HISTORY_BOOKMARKS",
    "TelephonyManager.getSubscriberId",
    "TelephonyManager.getDeviceId",
    "GET_ACCOUNTS",
    "chmod",
    "android.telephony.gsm.SmsManager",
    "TelephonyManager.getLine1Number",
    "Ljava.net.URLDecoder",
    "android.intent.action.BOOT_COMPLETED",
    "READ_PHONE_STATE",
    "CHANGE_NETWORK_STATE",
    "WRITE_EXTERNAL_STORAGE",
    "Ljava.lang.Object.getClass",
    "Ljava.lang.Class.getCanonicalName",
    "ACCESS_COARSE_LOCATION",
    "android.content.pm.PackageInfo",
    "Ljava.lang.Class.cast",
    "onBind",
    "findClass",
    "WRITE_SETTINGS",
    "HttpGet.init",
    "ClassLoader",
]

# Step 1: Decompile APK using APKTool
print("Decompiling APK using APKTool...", flush=True)

command = [r"C:\apktool\apktool.bat", "d", apk_path, "-o", output_dir, "--force"]
try:
    subprocess.run(command, check=True, stdout=None, stderr=None, text=True)
    print("APK decompiled successfully.", flush=True)
except subprocess.CalledProcessError as e:
    print(f"Error during decompilation: {e.stderr}", flush=True)
    exit(1)


# Step 2: Analyze AndroidManifest.xml for permissions
feature_presence = {feature: 0 for feature in features}
manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
if os.path.exists(manifest_path):
    print("Analyzing AndroidManifest.xml...", flush=True)
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    for permission in root.findall(".//uses-permission"):
        permission_name = permission.attrib.get("{http://schemas.android.com/apk/res/android}name", "")
        normalized_name = permission_name.split(".")[-1]  # Extract the permission name
        if normalized_name in features:
            feature_presence[normalized_name] = 1
            print(f"Found feature in manifest: {normalized_name}", flush=True)

# Step 3: Analyze .smali files for feature usage
print("Analyzing .smali files...", flush=True)
for root, dirs, files in os.walk(output_dir):
    for file in files:
        if file.endswith(".smali"):
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as smali_file:
                content = smali_file.read()
                for feature in features:
                    if feature in content:
                        feature_presence[feature] = 1
                        print(f"Found feature in smali: {feature} (File: {file_path})", flush=True)

# Step 4: Prepare features for model predictions
# Create a feature vector based on the presence of features
feature_vector = np.array([feature_presence[feature] for feature in features]).reshape(1, -1)

# Step 5: Load the LightGBM model and make a prediction
lightgbm_model_path = r"optimal_lightgbm_model.pkl"  # Path to LightGBM model
lightgbm_model = load(lightgbm_model_path)
lightgbm_prediction = lightgbm_model.predict(feature_vector)
lightgbm_result = "Malicious" if lightgbm_prediction[0] == 1 else "Benign"

print("\n=== Prediction Results ===", flush=True)
print(f"LightGBM Prediction: {lightgbm_result}", flush=True)

# Step 6: If LightGBM result is benign, run the Isolation Forest model
if lightgbm_result == "Benign":
    print("Running Isolation Forest for further validation...", flush=True)
    isolation_model_path = r"isolation_forest_model.pkl"  # Path to Isolation Forest model
    isolation_model = load(isolation_model_path)
    # Create the feature vector as a Pandas DataFrame with correct column names
    feature_vector_df = pd.DataFrame(feature_vector, columns=features)

    # Make prediction using Isolation Forest model
    isolation_prediction = isolation_model.predict(feature_vector_df)  # Pass DataFrame with feature names
    isolation_result = "Malicious" if isolation_prediction[0] == -1 else "Benign"

    print(f"Isolation Forest Prediction: {isolation_result}", flush=True)

    # Final decision based on Isolation Forest result
    if isolation_result == "Malicious":
        print("\nFinal Prediction: Malicious", flush=True)
    else:
        print("\nFinal Prediction: Benign", flush=True)
else:
    print("\nFinal Prediction: Malicious", flush=True)



