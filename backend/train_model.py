import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# 1. Load dataset
df = pd.read_csv("packets_dataset.csv")

# Keep only numeric features for ML
X = df[["size"]]   # (later we can add more features like encoded IPs)
y = df["anomaly"].astype(int)  # convert True/False → 1/0

# 2. Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train Isolation Forest
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X_train)

# 4. Predictions
y_pred = model.predict(X_test)
y_pred = [1 if val == -1 else 0 for val in y_pred]  # convert to 0/1

print("\nModel Performance:\n")
print(classification_report(y_test, y_pred))

# 5. Save model
joblib.dump(model, "anomaly_model.pkl")
print("✅ Model saved as anomaly_model.pkl")


