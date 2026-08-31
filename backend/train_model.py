import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score
from feature_extractor import extract_features, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_rf_model.pkl")

# Representative URLs dataset (Legitimate + Phishing) for model training
TRAINING_URL_SAMPLES = [
    # --- Legitimate URLs (Label: 0) ---
    ("https://www.google.com", 0),
    ("https://www.github.com/developer/repo", 0),
    ("https://www.wikipedia.org/wiki/Main_Page", 0),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0),
    ("https://www.microsoft.com/en-us/store", 0),
    ("https://www.apple.com/macbook-pro", 0),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0),
    ("https://stackoverflow.com/questions/123456", 0),
    ("https://www.python.org/downloads", 0),
    ("https://fastapi.tiangolo.com/tutorial", 0),
    ("https://scikit-learn.org/stable/index.html", 0),
    ("https://developer.mozilla.org/en-US/docs/Web", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://www.bbc.com/news/world", 0),
    ("https://www.reddit.com/r/programming", 0),
    ("https://www.linkedin.com/in/profile", 0),
    ("https://www.dropbox.com/home", 0),
    ("https://www.cloudflare.com/learning/security", 0),
    ("https://docs.github.com/en/actions", 0),
    ("https://chat.openai.com", 0),
    ("https://www.bing.com/search?q=test", 0),
    ("https://medium.com/@author/story-title", 0),
    ("https://hub.docker.com/_/python", 0),
    ("https://pypi.org/project/fastapi/", 0),
    ("https://www.w3schools.com/js/default.asp", 0),

    # --- Phishing / Malicious URLs (Label: 1) ---
    ("http://192.168.1.1/login-paypal-security-update-account/verify.php", 1),
    ("http://paypal-security-update-account.com/login.html", 1),
    ("http://login.apple.com.verify-id-account-restore.tk/auth", 1),
    ("http://www.google.com.account-signin-verification-page.info", 1),
    ("http://amazon-account-billing-alert.com/signin?claim=bonus", 1),
    ("http://10.0.0.1/bank-of-america/login.php?user=admin@test.com", 1),
    ("http://bit.ly/secure-banking-login-claim", 1),
    ("http://netflix-billing-update-subscription.xyz/verify", 1),
    ("http://microsoft-outlook-credential-reset.top/login", 1),
    ("http://crypto-wallet-free-bonus-claim.online/airdrop", 1),
    ("http://account-validation-security-code.site/pass_reset.php", 1),
    ("http://paypal.com@verify-credentials-access-account.net/login", 1),
    ("http://192.168.0.105/paypal_identity_verification/login.asp", 1),
    ("http://secure-update-bank.com//login//verify.php?token=123", 1),
    ("http://www.facebook.com-login-account-recovery-system.ru/auth", 1),
    ("http://tinyurl.com/apple-id-verify-account-now", 1),
    ("http://chase-bank-online-alert-verification.com/login.htm", 1),
    ("http://wellsfargo-update-customer-credential.cc/signin", 1),
    ("http://instagram-blue-tick-claim-free-bonus.pw/verify", 1),
    ("http://binance-wallet-security-restore.club/auth/login", 1),
    ("http://203.0.113.195/secure/login_bank.html", 1),
    ("http://login-google-account-verify-access.gq/signin", 1),
    ("http://dhl-package-tracking-update-address.top/confirm", 1),
    ("http://usps-redelivery-confirm-account.site/pay", 1),
    ("http://service-paypal-account-locked-restore.biz/login", 1)
]

def generate_augmented_dataset(base_samples, n_copies=30):
    """
    Augments base dataset with minor variations to build a robust Random Forest training set.
    """
    X_list = []
    y_list = []

    for url, label in base_samples:
        feat = extract_features(url)["feature_vector"]
        X_list.append(feat)
        y_list.append(label)

        # Add augmented variations with minor feature noise
        for _ in range(n_copies):
            noisy_feat = list(feat)
            # Add slight variance to continuous values like URL length & digit ratio
            noisy_feat[0] = max(5, int(noisy_feat[0] + np.random.randint(-3, 4)))
            noisy_feat[11] = max(0.0, min(1.0, noisy_feat[11] + np.random.normal(0, 0.02)))
            X_list.append(noisy_feat)
            y_list.append(label)

    return np.array(X_list), np.array(y_list)

def train_and_save_model():
    print("Starting Random Forest Model Training for Live Phishing Detection...")
    X, y = generate_augmented_dataset(TRAINING_URL_SAMPLES, n_copies=40)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train Random Forest Classifier
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        min_samples_split=2,
        criterion="gini"
    )
    rf_classifier.fit(X_train, y_train)

    # Evaluate model
    y_pred = rf_classifier.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)

    print(f"Model Training Completed Successfully!")
    print(f"Dataset Size: {len(X)} samples")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Feature Importance analysis
    importances = rf_classifier.feature_importances_
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True):
        print(f"Feature: {name:<28} Importance: {imp:.4f}")

    # Save trained model to file
    model_data = {
        "model": rf_classifier,
        "feature_names": FEATURE_NAMES,
        "accuracy": acc,
        "precision": prec,
        "recall": rec
    }
    joblib.dump(model_data, MODEL_PATH)
    print(f"\nSaved trained model artifact to: {MODEL_PATH}")
    return model_data

if __name__ == "__main__":
    train_and_save_model()
