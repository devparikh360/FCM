def clamp(x, lo=0, hi=100): 
    return max(lo, min(hi, int(round(x))))

def score_from_reasons(reasons):
    score = sum(r["points"] for r in reasons)
    return clamp(score)

def status_from_score(score):
    if score >= 70: return "High Risk"
    if score >= 40: return "Medium Risk"
    return "Safe"
