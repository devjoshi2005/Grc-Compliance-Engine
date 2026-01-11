import json
import re
import os

output_dir = "extracted_remediations"
os.makedirs(output_dir, exist_ok=True)

with open('grc_remediation_plan.json', 'r') as f:
    plan = json.load(f)

hcl_regex = r"```(?:hcl)?\s*(.*?)\s*```"

for i, item in enumerate(plan):
    analysis_text = item.get('analysis', '')
    resource_id = item.get('resource', 'unknown').split('/')[-1]
    
    matches = list(re.finditer(hcl_regex, analysis_text, re.DOTALL))
    
    if not matches:
        print(f"Skipping Item {i}: No HCL code found.")
        continue

    for j, match in enumerate(matches):
        code_content = match.group(1).strip()
        
        filename = f"item_{i}_block_{j}_{resource_id}.tf"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as tf_file:
            tf_file.write(code_content)
            
    print(f"Item {i}: Extracted {len(matches)} blocks for {resource_id}")