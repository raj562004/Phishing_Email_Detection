import re

SUSPICIOUS_SUBJECTS = [
    "urgent",
    "verify",
    "account suspended",
    "payment failed",
    "action required",
    "security alert",
    "confirm",
    "invoice",
    "winner",
    "congratulations",
    "limited time",
    "your account",
]

SUSPICIOUS_BODY = [
    "click here",
    "verify account",
    "login",
    "password",
    "credit card",
    "bank account",
    "update account",
    "confirm identity",
    "wire transfer",
    "gift card",
    "bitcoin",
    "crypto",
    "security alert",
    "reset password",
    "act now",
    "within 24 hours",
    "immediately",
    "claim your reward",
    "limited offer",
    "avoid suspension",
]

MONEY_WORDS = [
    "invoice",
    "payment",
    "refund",
    "money",
    "salary",
    "reward",
    "prize",
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".tk",
    ".gq",
    ".cf",
    ".ml",
    ".ga",
    ".click",
    ".zip",
    ".review",
    ".country",
    ".work",
    ".invalid"
]

FREE_EMAILS = [
    "@gmail.com",
    "@yahoo.com",
    "@hotmail.com",
    "@outlook.com",
]

KNOWN_BRANDS = [
    "paypal",
    "amazon",
    "google",
    "apple",
    "microsoft",
    "netflix",
    "facebook",
    "bank",
]


def analyze_email(email):

    score = 0

    highRiskFactors = []

    warnings = []

    subject = email.get("subject", "").lower()

    body = email.get("body", "").lower()

    sender = email.get("sender_email", "").lower()

    urls = email.get("urls", [])

    #########################################################
    # SUBJECT
    #########################################################

    for word in SUSPICIOUS_SUBJECTS:

        if word in subject:

            score += 10

            highRiskFactors.append({

                "type":"Subject",

                "detail":f'Subject contains "{word}"'

            })

    #########################################################
    # BODY
    #########################################################

    for word in SUSPICIOUS_BODY:

        if word in body:

            score += 8

            highRiskFactors.append({

                "type":"Body",

                "detail":f'Body contains "{word}"'

            })

    #########################################################
    # MONEY
    #########################################################

    for word in MONEY_WORDS:

        if word in body:

            score += 5

    #########################################################
    # EXCLAMATION
    #########################################################

    exclamation = subject.count("!") + body.count("!")

    if exclamation >= 3:

        score += 5

        warnings.append({

            "type":"Formatting",

            "detail":"Too many exclamation marks"

        })

    #########################################################
    # UPPERCASE SUBJECT
    #########################################################

    if len(subject) > 10 and subject == subject.upper():

        score += 10

        warnings.append({

            "type":"Formatting",

            "detail":"Subject is fully uppercase"

        })

    #########################################################
    # SENDER DOMAIN
    #########################################################

    for tld in SUSPICIOUS_TLDS:

        if sender.endswith(tld):

            score += 20

            highRiskFactors.append({

                "type":"Sender",

                "detail":f"Suspicious sender domain ({tld})"

            })

    #########################################################
    # BRAND USING GMAIL
    #########################################################

    for brand in KNOWN_BRANDS:

        if brand in sender:

            for domain in FREE_EMAILS:

                if sender.endswith(domain):

                    score += 20

                    highRiskFactors.append({

                        "type":"Sender",

                        "detail":"Brand using free email provider"

                    })

    #########################################################
    # LINKS
    #########################################################

    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"

    for url in urls:

        url = url.lower()

        # HTTP instead of HTTPS
        if url.startswith("http://"):

            score += 15

            warnings.append({

                "type": "Link",

                "detail": "HTTP link detected"

            })

        # Long URL
        if len(url) > 100:

            score += 10

            warnings.append({

                "type": "Link",

                "detail": "Very long URL"

            })

        # @ symbol
        if "@" in url:

            score += 20

            highRiskFactors.append({

                "type": "Link",

                "detail": "URL contains @ symbol"

            })

        # Too many dots
        if len(re.findall(r"\.", url)) > 4:

            score += 10

            warnings.append({

                "type": "Link",

                "detail": "Too many subdomains"

            })

        # IP address URL
        if re.search(ip_pattern, url):

            score += 25

            highRiskFactors.append({

                "type": "Link",

                "detail": "IP address used instead of domain"

            })

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:

            if tld in url:

                score += 25

                highRiskFactors.append({

                    "type": "Link",

                    "detail": f"Suspicious domain ({tld})"

                })

                break

        # Brand impersonation
        for brand in KNOWN_BRANDS:

            if brand in url:

                if ".invalid" in url or ".xyz" in url or ".top" in url:

                    score += 30

                    highRiskFactors.append({

                        "type": "Link",

                        "detail": f"Possible {brand.title()} impersonation"

                    })

                    break

    #########################################################
    # MANY LINKS
    #########################################################

    if len(urls) > 5:

        score += 10

        warnings.append({

            "type":"Link",

            "detail":"Email contains many hyperlinks"

        })

    #########################################################
    # VERY SHORT EMAIL
    #########################################################

    if len(body) < 30:

        score += 5

        warnings.append({

            "type":"Content",

            "detail":"Very short email"

        })

    #########################################################
    # FINAL VERDICT
    #########################################################

    verdict = "Legitimate"

    if score >= 60:

        verdict = "Phishing"

    elif score >= 30:

        verdict = "Suspicious"

    return {

        "riskScore": score,

        "verdict": verdict,

        "highRiskFactors": highRiskFactors,

        "warnings": warnings

    }