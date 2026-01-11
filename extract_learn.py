import json
import os
from llama_index.core import VectorStoreIndex, StorageContext
from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI
import chromadb

COMPLIANCE_DB_PATH = "./compliance_db1"
LLM_MODEL = "gpt-4o"

llm = OpenAI(model=LLM_MODEL, temperature=0,api_key=os.getenv("OPENAI_API_KEY"))
embed_model = OpenAIEmbedding(api_key=os.getenv("OPENAI_API_KEY"))

chroma_client = chromadb.PersistentClient(path=COMPLIANCE_DB_PATH)
chroma_collection = chroma_client.get_or_create_collection("compliance")

vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
storage_context = StorageContext.from_defaults(vector_store=vector_store)

index = VectorStoreIndex.from_vector_store(
    vector_store, 
    storage_context=storage_context,
    embed_model=embed_model
)

qa_engine = index.as_query_engine(
    llm=llm,
    similarity_top_k=3,
    response_mode="compact"
)

def build_grc_prompt(finding_summary):
    return f"""
You are a Senior GRC Cloud Architect. 
Below is a Prowler security finding and relevant compliance context (NIST, ISO, CIS).

INSTRUCTIONS:
1. Map this finding to the specific NIST/PCI control in the context.
2. Explain the "Business Risk" for a CISO.
3. Provide the EXACT Terraform (HCL) code to fix this. Use current best practices.

COMPLIANCE CONTEXT:
{{context_str}}

PROWLER FINDING:
{json.dumps(finding_summary, indent=2)}
RESPONSE:
"""
SEVERITY=["Critical","High"]

def run_grc_analysis(json_files):
    all_remediations = []
    
    for file_path in json_files:
        print(f"--- Analyzing {file_path} ---")
        with open(file_path, 'r') as f:
            findings = json.load(f)
            
        for finding in findings:
            if finding.get("status_code") == "FAIL" and finding.get("severity") in SEVERITY and finding.get("status") == "New":
                finding_summary = {
                    "Title": finding.get("finding_info", {}).get("title"),
                    "Resource": finding.get("resources", [{}])[0].get("uid"),
                    "Severity": finding.get("severity"),
                    "Description": finding.get("finding_info", {}).get("desc"),
                    "Risk": finding.get("risk_details"),
                    "Remediation": finding.get("remediation", {}).get("desc"),
                }
                
                print(f"Processing: {finding_summary['Title']}")
                
                query_str = build_grc_prompt(finding_summary)
                response = qa_engine.query(query_str)
                
                all_remediations.append({
                    "resource": finding_summary["Resource"],
                    "analysis": response.response.strip()
                })
                
    return all_remediations

prowler_files = ["aws_prowler_scan.json", "azurescan.json"]
results = run_grc_analysis(prowler_files)

with open("grc_remediation_plan.json", "w") as out:
    json.dump(results, out, indent=4)

print("Analysis Complete. Results saved to grc_remediation_plan.json")   