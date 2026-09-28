import os

dirs = [
    "app/services/analysis",
    "app/services/tools/handlers",
    "app/services/investigation",
    "app/services", # for risk_score/decision_engine
    "app/models", # for DB
    "app/repositories",
    "app/api"
]

def count_lines(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return sum(1 for line in f)

for d in dirs:
    print(f"--- {d} ---")
    if not os.path.exists(d):
        print("Not found")
        continue
    for root, _, files in os.walk(d):
        if "__pycache__" in root: continue
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                lines = count_lines(path)
                print(f"{lines}\t{path}")

