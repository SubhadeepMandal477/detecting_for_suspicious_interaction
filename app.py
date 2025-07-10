import streamlit as st
import numpy as np
import pandas as pd
import joblib
from tensorflow.keras.models import load_model

# Load model and preprocessor
model = load_model("web_threat_detector.h5")
scaler = joblib.load("scaler.pkl")
feature_columns = joblib.load("feature_columns.pkl")

st.title("Cyber threat detector")

st.write("Fill in the network request parameters to detect if it's suspicious or not.")

input_data = {}

input_data['Source Port'] = st.number_input("Source Port", min_value=0, max_value=65535, value=80)
input_data['Destination Port'] = st.number_input("Destination Port", min_value=0, max_value=65535, value=443)
input_data['Packet Length'] = st.number_input("Packet Length", min_value=1, value=500)
input_data['Anomaly Scores'] = st.number_input("Anomaly Score", min_value=0.0, value=30.0)

input_data['Protocol'] = st.selectbox("Protocol", ['TCP', 'UDP', 'ICMP'])
input_data['Packet Type'] = st.selectbox("Packet Type", ['Data', 'Control'])
input_data['Traffic Type'] = st.selectbox("Traffic Type", ['HTTP', 'FTP', 'DNS'])
input_data['Attack Signature'] = st.selectbox("Attack Signature", ['Known Pattern A', 'Known Pattern B'])
input_data['Action Taken'] = st.selectbox("Action Taken", ['Blocked', 'Logged', 'Ignored'])
input_data['Severity Level'] = st.selectbox("Severity Level", ['Low', 'Medium', 'High'])
input_data['Network Segment'] = st.selectbox("Network Segment", ['Segment A', 'Segment B', 'Segment C'])
input_data['Log Source'] = st.selectbox("Log Source", ['Server', 'Firewall'])

input_df = pd.DataFrame([input_data])

input_encoded = pd.get_dummies(input_df)
input_encoded = input_encoded.reindex(columns=feature_columns, fill_value=0)

input_scaled = scaler.transform(input_encoded)

if st.button(" Predict Suspicion"):
    pred_prob = model.predict(input_scaled)[0][0]
    prediction = " Suspicious" if pred_prob > 0.5 else " Normal"
    st.subheader(f"Prediction: {prediction}")
    st.write(f"Confidence: {pred_prob * 100:.2f}%")
