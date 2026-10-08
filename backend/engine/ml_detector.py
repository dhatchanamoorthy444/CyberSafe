import os
import pickle


def load_model(path: str = "model.pkl"):
    if os.path.exists(path):
        try:
            with open(path, "rb") as f:
                return pickle.load(f)
        except Exception:
            return None
    return None


def ml_detect(url: str) -> int:
    model = load_model()
    if model:
        try:
            # Minimal feature vector for demonstration
            features = [len(url), len(url.split("/")), url.count("-"), url.count("?"), url.count("=")]
            score = model.predict([features])[0]
            return int(score)
        except Exception:
            pass
    # Fallback deterministic heuristic
    return 30 if len(url) > 100 else 10
