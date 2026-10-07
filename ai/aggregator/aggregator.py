"""CyberSafe AI Aggregator — complementary synthesis"""
def aggregate(groq, gemini, verdict, findings, url):
    agreement = "HIGH" if (groq.get("status")=="available" and gemini.get("status")=="available") else "MIXED"
    return {"consensus":agreement,"cybersafe_authoritative":verdict,"groq":groq.get("summary","Unavailable"),"gemini":gemini.get("explanation","Unavailable"),"key_findings":[f.get("rule_id","f") for f in findings]}
