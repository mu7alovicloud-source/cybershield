def explain_risk(score, level):
    if level=="CRITICAL": return f"Risk {score}/100. Immediate investigation is recommended."
    if level=="HIGH": return f"Risk {score}/100. High-risk indicators require investigation."
    if level=="MEDIUM": return f"Risk {score}/100. Additional analysis is recommended."
    return f"Risk {score}/100. No strong malicious indicators were detected."
