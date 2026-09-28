import re

with open('app/services/investigation/tool_registry.py', 'r', encoding='utf-8') as f:
    content = f.read()

tools_to_disable = [
    'spf_dkim_dmarc', 'header_parse', 'relay_reconstruction',
    'deterministic_heuristics', 'url_reputation', 'header_ml',
    'html_analysis', 'attachment_static_analysis',
    'domain_intelligence', 'ip_intelligence'
]

for tool in tools_to_disable:
    pattern = r'("' + tool + r'": ToolDefinition\([\s\S]*?enabled=)True(,\s*\n\s*\),?)'
    content = re.sub(pattern, r'\g<1>False\g<2>', content)

with open('app/services/investigation/tool_registry.py', 'w', encoding='utf-8') as f:
    f.write(content)
