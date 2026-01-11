import json
import pandas as pd
import pyfair 

THREAT_EVENT_FREQUENCY_DAYS = {
    "Critical": {"low": 12, "mode": 52, "high": 365},  
    "High":     {"low": 4,  "mode": 12, "high": 24},   
}

LOSS_MAGNITUDE_MAP_DOLLARS = {
    "Highly Sensitive": {"low": 1_000_000, "mode": 6_080_000, "high": 50_000_000}, 
    "Sensitive":        {"low": 250_000,   "mode": 1_500_000, "high": 5_000_000},
    "Internal":         {"low": 25_000,    "mode": 150_000,   "high": 750_000},
}

def load_data():
    with open("steampipe_tags1.json", "r") as f:
        assets = json.load(f)
    with open("filtered_prowler_findings1.json", "r") as f:
        findings = json.load(f)
    return assets, findings

def calculate_risk():
    assets, findings = load_data()
    total_risk_exposure = 0
    report_data = []

    print("--- Running Professional GRC Risk Simulation ---")

    for finding in findings:
        r_uid = finding.get("resources", [{}])[0].get("uid", "unknown")
        r_name_raw = r_uid.split("/")[-1].split(":")[-1] 
        
        asset_key = next((k for k in assets.keys() if r_name_raw in k.lower()), "")
        asset_details = assets.get(asset_key, []) if asset_key else []
        
        context = {
            "class": "Internal",
            "is_public": False,
            "retention": 30,      # Default standard
            "is_active": True,    # Assume active
            "soft_delete": True   # Assume enabled
        }

        if any(x in r_uid for x in ["iam", "service_principal", "role", "user"]):
            context["class"] = "Sensitive"  
            
        elif any(x in r_uid for x in ["sql", "db", "storage", "bucket", "vault"]):
            context["class"] = "Highly Sensitive"
            
        elif any(x in r_uid for x in ["datasync", "data_factory", "factory"]):
            context["class"] = "Sensitive"   
            
        elif any(x in r_uid for x in ["cloudwatch", "monitor", "logs", "workspace"]):
            context["class"] = "Internal"    
            
        else:
            context["class"] = "Internal"    

        for item in asset_details:
            clean = item.strip("{} ")
            if ":" not in clean: continue
            
            key, val = [x.strip().lower() for x in clean.split(":", 1)]

            

            # 1. Classification
            if "dataclassification" in key:
                context["class"] = val.title()
            
            # 2. Public Exposure
            if "public" in key and val in ["true", "enabled"]:
                context["is_public"] = True
            
            # 3. Operational Status
            if "status" in key or "account_enabled" in key:
                if val in ["false", "disabled", "deleted", "failed"]:
                    context["is_active"] = False

            # 4. Resilience (Soft Delete)
            if "soft_delete" in key and val == "false":
                context["soft_delete"] = False

            # 5. Forensics (Retention)
            if "retention" in key:
                try: context["retention"] = int(val.split()[0])
                except: pass

        severity = finding.get("severity", "High")
        tef = THREAT_EVENT_FREQUENCY_DAYS.get(severity, THREAT_EVENT_FREQUENCY_DAYS["High"]).copy()
        lm = LOSS_MAGNITUDE_MAP_DOLLARS.get(context["class"], LOSS_MAGNITUDE_MAP_DOLLARS["Internal"]).copy()

        if not context["is_active"]:
            ale = 0 # No risk if the resource is dead
        else:
            if context["is_public"]:
                tef = {k: v * 2 for k, v in tef.items()}
            
            if not context["soft_delete"]:
                lm = {k: v * 1.25 for k, v in lm.items()}
            
            if context["retention"] < 14:
                lm = {k: v * 1.15 for k, v in lm.items()}

            model = pyfair.FairModel(name=r_name_raw, n_simulations=10000)

            model.input_data('Loss Event Frequency', low=tef['low'], mode=tef['mode'], high=tef['high'])
            model.input_data('Loss Magnitude', low=lm['low'], mode=lm['mode'], high=lm['high'])

            model.calculate_all()
            
            results = model.export_results()
            print(f"Available columns: {results.columns.tolist()}")
            ale = results['Risk'].iloc[0]

        total_risk_exposure += ale
        report_data.append({
            "Resource": r_name_raw,
            "Severity": severity,
            "Class": context["class"],
            "Public": context["is_public"],
            "Retention": context["retention"],
            "ALE": round(ale, 2)
        })

    df = pd.DataFrame(report_data).sort_values(by="ALE", ascending=False)
    print(f"\nTOTAL ANNUAL LOSS EXPOSURE: ${total_risk_exposure:,.2f}")
    df.to_json("risk_quantification_report.json", orient="records", indent=4)
    return df

if __name__ == "__main__":
    calculate_risk()