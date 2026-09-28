import os
import re

dirs_to_check = [
    "app/services/analysis",
    "app/services/tools/handlers",
    "app/services/investigation",
    "app/services/risk",
    "app/models",
    "app/repositories",
    "app/api"
]

report_rows = []

def analyze_file(path, lines):
    content = "".join(lines)
    
    # external API calls
    api_calls = re.findall(r'(requests\.|httpx\.|aiohttp)', content)
    has_api = bool(api_calls)
    
    # Evidence mixing fact with interpretation (confidence = based on value instead of observation quality)
    # Looking for heuristic/evidence creation where confidence is variable or questionable
    
    # Just output findings
    return {
        "lines": len(lines),
        "api": has_api
    }

print("| Capability | Already Exists | Quality | Missing/Weak | Recommended Change | Priority |")
print("|---|---|---|---|---|---|")

for root, _, files in os.walk("app"):
    if "__pycache__" in root: continue
    if not any(root.replace("\\", "/").startswith(d) for d in dirs_to_check): continue
    
    for f in files:
        if not f.endswith(".py"): continue
        path = os.path.join(root, f)
        with open(path, "r", encoding="utf-8") as file:
            lines = file.readlines()
        
        if len(lines) <= 30:
            continue
            
        stats = analyze_file(path, lines)
        if stats["api"]:
            print(f"| {path} | Yes | Poor | External API call found: {path} | Move API call to async enrichment layer | P0 |")

