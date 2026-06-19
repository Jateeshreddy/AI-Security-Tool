def calculate_risk_score(malicious, suspicious):

    score = 0

    if malicious > 0:
        score += 40

    if suspicious > 0:
        score += 10

    if score == 0:
        level = "Safe"

    elif score <= 20:
        level = "Low Risk"

    elif score <= 40:
        level = "Medium Risk"

    elif score <= 60:
        level = "High Risk"

    else:
        level = "Critical"

    return score, level