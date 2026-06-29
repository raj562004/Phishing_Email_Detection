# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import joblib
# import numpy as np
# import requests
# import re

# from heuristic import analyze_email

# app = Flask(__name__)
# CORS(app)

# # ==============================
# # CONFIG
# # ==============================

# GOOGLE_API_KEY = "AIzaSyD6t3luyyv1bkK2CT_ZwWfmFLcVdpI5ta4"

# # ==============================
# # LOAD MODEL
# # ==============================

# model = joblib.load("enron_phishing_model.pkl")
# tfidf = joblib.load("enron_tfidf.pkl")


# # ==============================
# # GOOGLE SAFE BROWSING
# # ==============================

# def check_google_safe_browsing(urls):

#     if len(urls) == 0:
#         return {
#             "malicious": False,
#             "detected_urls": []
#         }

#     endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

#     payload = {
#         "client": {
#             "clientId": "phishing-extension",
#             "clientVersion": "1.0"
#         },
#         "threatInfo": {
#             "threatTypes": [
#                 "MALWARE",
#                 "SOCIAL_ENGINEERING",
#                 "UNWANTED_SOFTWARE",
#                 "POTENTIALLY_HARMFUL_APPLICATION"
#             ],
#             "platformTypes": [
#                 "ANY_PLATFORM"
#             ],
#             "threatEntryTypes": [
#                 "URL"
#             ],
#             "threatEntries": [{"url": u} for u in urls]
#         }
#     }

#     response = requests.post(endpoint, json=payload)

#     result = response.json()

#     if "matches" not in result:

#         return {
#             "malicious": False,
#             "detected_urls": []
#         }

#     bad_urls = []

#     for match in result["matches"]:

#         bad_urls.append(match["threat"]["url"])

#     return {

#         "malicious": True,

#         "detected_urls": bad_urls

#     }


# # ==============================
# # PREPROCESS ML
# # ==============================

# def preprocess_input(subject,
#                      body,
#                      url,
#                      sender_email,
#                      received_path):

#     url_len = len(url)

#     dot_count = url.count(".")

#     has_ip = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

#     sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

#     domain_mismatch = 1 if sender_domain not in received_path else 0

#     clean_text = (subject + " " + body).lower()

#     clean_text = re.sub(r"[^a-z\s]", "", clean_text)

#     text_vector = tfidf.transform([clean_text]).toarray()

#     metadata = np.array([[

#         url_len,

#         dot_count,

#         has_ip,

#         0,

#         domain_mismatch,

#         0

#     ]])

#     return np.hstack((metadata, text_vector))


# # ==============================
# # API
# # ==============================

# @app.route("/predict", methods=["POST"])
# def predict():

#     data = request.json

#     subject = data.get("subject", "")

#     body = data.get("body", "")

#     sender = data.get("sender_email", "")

#     received = data.get("received_path", "")

#     urls = data.get("urls", [])

#     first_url = urls[0] if len(urls) else ""

#     ############################################
#     # ML
#     ############################################

#     features = preprocess_input(

#         subject,

#         body,

#         first_url,

#         sender,

#         received

#     )

#     prediction = model.predict(features)[0]

#     confidence = float(model.predict_proba(features)[0][1])

#     ml_label = "phishing" if prediction == 1 else "legitimate"

#     ############################################
#     # GOOGLE SAFE BROWSING
#     ############################################

#     google_result = check_google_safe_browsing(urls)

#     ############################################
#     # HEURISTIC
#     ############################################

#     heuristic_result = analyze_email({

#         "subject": subject,

#         "body": body,

#         "sender_email": sender,

#         "urls": urls

#     })

#     ############################################
#     # FINAL DECISION
#     ############################################

#     final_prediction = "Legitimate"

#     if google_result["malicious"]:

#         final_prediction = "Phishing"

#     elif ml_label == "phishing" and heuristic_result["riskScore"] >= 40:

#         final_prediction = "Phishing"

#     elif heuristic_result["riskScore"] >= 70:

#         final_prediction = "Phishing"

#     elif heuristic_result["riskScore"] >= 40:

#         final_prediction = "Suspicious"

#     ############################################
#     # RESPONSE
#     ############################################

#     return jsonify({

#         "ml": {

#             "label": ml_label,

#             "confidence": confidence

#         },

#         "google": google_result,

#         "heuristic": heuristic_result,

#         "final_prediction": final_prediction

#     })


# if __name__ == "__main__":

#     app.run(debug=True, port=5000)


from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import requests
import re

from heuristic import analyze_email

app = Flask(__name__)
CORS(app)

# =====================================================
# CONFIGURATION
# =====================================================

import os

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# =====================================================
# LOAD ML MODEL
# =====================================================

model = joblib.load("enron_phishing_model.pkl")
tfidf = joblib.load("enron_tfidf.pkl")

# =====================================================
# GOOGLE SAFE BROWSING
# =====================================================

def check_google_safe_browsing(urls):
    """
    Checks every URL using Google Safe Browsing.
    Returns:
    {
        malicious: bool,
        detected_urls: [],
        matches:[]
    }
    """

    if not urls:
        return {
            "malicious": False,
            "detected_urls": [],
            "matches": []
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        f"threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "phishing-extension",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {"url": url} for url in urls
            ]
        }
    }

    try:

        response = requests.post(
            endpoint,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        result = response.json()

    except Exception as e:

        print("Google Safe Browsing Error:", e)

        return {
            "malicious": False,
            "detected_urls": [],
            "matches": [],
            "error": str(e)
        }

    if "matches" not in result:

        return {
            "malicious": False,
            "detected_urls": [],
            "matches": []
        }

    bad_urls = []

    for match in result["matches"]:

        url = match["threat"]["url"]

        if url not in bad_urls:
            bad_urls.append(url)

    return {

        "malicious": True,

        "detected_urls": bad_urls,

        "matches": result["matches"]

    }


# =====================================================
# ML PREPROCESSING
# =====================================================

def preprocess_input(subject, body, url, sender_email, received_path):

    # -----------------------------
    # Clean text (same as training)
    # -----------------------------
    

    clean_text = (str(subject) + " " + str(body)).lower()

    clean_text = re.sub(r"http\S+|www\S+|https\S+", " ", clean_text)

    clean_text = re.sub(r"[^a-z\s]", " ", clean_text)

    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    X_text = tfidf.transform([clean_text]).toarray()

    # -----------------------------
    # Metadata (14 Features)
    # -----------------------------

    # ===== Signal Features =====

    poi_present = 0

    suspicious_folders = 0

    unique_sender = 0

    low_comm = 0

    contains_reply_forward = 1 if re.search(
        r"\b(fwd|fw|re)\b",
        subject.lower()
    ) else 0

    sender_type_enc = (
        0
        if sender_email.lower().endswith("@enron.com")
        else 1
    )

    # ===== Derived Features =====

    subject_len = len(subject)

    subject_has_caps = (
        1
        if re.search(r"[A-Z]{3,}", subject)
        else 0
    )

    subject_exclaim = subject.count("!")

    body_len = len(body)

    body_link_count = len(
        re.findall(r"https?://", body)
    )

    body_exclaim = body.count("!")

    body_word_count = len(body.split())

    has_fwd_subject = contains_reply_forward

    metadata = np.array([[
        poi_present,
        suspicious_folders,
        unique_sender,
        low_comm,
        contains_reply_forward,
        sender_type_enc,

        subject_len,
        subject_has_caps,
        subject_exclaim,

        body_len,
        body_link_count,
        body_exclaim,
        body_word_count,

        has_fwd_subject
    ]])

    return np.hstack((metadata, X_text))


# =====================================================
# FINAL DECISION LOGIC
# =====================================================

def get_final_prediction(
    ml_label,
    ml_confidence,
    google_result,
    heuristic_result
):
    """
    Combines all three detection layers.
    """

    if google_result["malicious"]:

        return "Phishing"

    if (
        ml_label == "phishing"
        and ml_confidence >= 0.70
    ):

        return "Phishing"

    if heuristic_result["riskScore"] >= 70:

        return "Phishing"

    if (
        heuristic_result["riskScore"] >= 40
        and ml_label == "phishing"
    ):

        return "Phishing"

    if heuristic_result["riskScore"] >= 40:

        return "Suspicious"

    if (
        ml_label == "phishing"
        and ml_confidence >= 0.55
    ):

        return "Suspicious"

    return "Legitimate"


# =====================================================
# PART 2 STARTS BELOW
# =====================================================
# =====================================================
# API
# =====================================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json()

        subject = data.get("subject", "")
        body = data.get("body", "")
        sender_email = data.get("sender_email", "")
        received_path = data.get("received_path", "")

        # Content.js sends a list of URLs
        urls = data.get("urls", [])

        # ML model was trained on one URL.
        # Use the first URL for feature extraction.
        # first_url = urls[0] if len(urls) > 0 else ""

        # # =============================================
        # # ML Prediction
        # # =============================================

        highest_probability = -1
        highest_prediction = 0
        ml_url = ""

        for url in urls if urls else [""]:

            features = preprocess_input(
                subject,
                body,
                url,
                sender_email,
                received_path
            )

            print("Feature shape:", features.shape)

            prediction = model.predict(features)[0]

            probability = model.predict_proba(features)[0][1]

            if probability > highest_probability:

                highest_probability = probability
                highest_prediction = prediction
                ml_url = url

        confidence = float(highest_probability)

        ml_label = (
            "phishing"
            if highest_prediction == 1
            else "legitimate"
        )

        # =============================================
        # Google Safe Browsing
        # =============================================

        google_result = check_google_safe_browsing(urls)

        # =============================================
        # Heuristic Analysis
        # =============================================

        heuristic_result = analyze_email({

            "subject": subject,

            "body": body,

            "sender_email": sender_email,

            "urls": urls

        })

        # =============================================
        # Final Decision
        # =============================================

        final_prediction = get_final_prediction(

            ml_label,

            confidence,

            google_result,

            heuristic_result

        )

        # =============================================
        # Response
        # =============================================

        return jsonify({

            "success": True,

            "final_prediction": final_prediction,

            "ml": {

                "label": ml_label,

                "confidence": round(confidence, 4),

                "evaluated_url": ml_url
                

            },

            "google": google_result,

            "heuristic": heuristic_result

        })

    except Exception as e:

        print(e)

        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


# =====================================================
# RUN
# =====================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )