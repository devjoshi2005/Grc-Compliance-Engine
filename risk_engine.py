import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any


THREAT_EVENT_FREQUENCY_DAYS = {
    "Critical": 0.30, 
    "High": 0.15,      
    "Medium": 0.05,    
    "Low": 0.01        
}

LOSS_MAGNITUDE_MAP_DOLLARS = {
    "Highly Sensitive": 1_000_000, 
    "Sensitive": 100_000,         
    "Internal": 10_000,           
    "Public": 1_000                
}

CONTROL_EFFECTIVENESS = {
    "mfa_enabled": 0.90,                 
    "encryption_enabled": 0.95,         
    "security_group_restricted": 0.80,   
    "iam_policy_least_privilege": 0.85,  
    "backup_enabled": 0.70,              
    "logging_enabled": 0.60,             
    "root_account_restricted": 0.95,    
    "default": 0.0                      
}

FINDING_CONTROL_EFFECTIVENESS = {
    "iam_administrator_access_with_mfa": 0.0,
    "iam_aws_attached_policy_no_administrative_privileges": 0.0,
    "iam_group_administrator_access_policy": 0.0,
    "iam_inline_policy_allows_privilege_escalation": 0.0,
    "iam_policy_allows_privilege_escalation": 0.0,
    "iam_role_administratoraccess_policy": 0.0,
    "iam_role_cross_service_confused_deputy_prevention": 0.0,
    "iam_no_root_access_key": 0.0,
    "iam_avoid_root_usage": 0.0,
    "iam_root_hardware_mfa_enabled": 0.90,
    
    "ec2_instance_port_cassandra_exposed_to_internet": 0.0,
    "ec2_instance_port_cifs_exposed_to_internet": 0.0,
    "ec2_instance_port_elasticsearch_kibana_exposed_to_internet": 0.0,
    "ec2_instance_port_ftp_exposed_to_internet": 0.0,
    "ec2_instance_port_kafka_exposed_to_internet": 0.0,
    "ec2_instance_port_kerberos_exposed_to_internet": 0.0,
    "ec2_instance_port_ldap_exposed_to_internet": 0.0,
    "ec2_instance_port_memcached_exposed_to_internet": 0.0,
    "ec2_instance_port_mongodb_exposed_to_internet": 0.0,
    "ec2_instance_port_mysql_exposed_to_internet": 0.0,
    "ec2_instance_port_oracle_exposed_to_internet": 0.0,
    "ec2_instance_port_postgresql_exposed_to_internet": 0.0,
    "ec2_instance_port_rdp_exposed_to_internet": 0.0,
    "ec2_instance_port_redis_exposed_to_internet": 0.0,
    "ec2_instance_port_sqlserver_exposed_to_internet": 0.0,
    "ec2_instance_port_ssh_exposed_to_internet": 0.0,
    "ec2_instance_port_telnet_exposed_to_internet": 0.0,
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports": 0.0,
    "ec2_securitygroup_allow_ingress_from_internet_to_any_port": 0.0,
    "ec2_securitygroup_default_restrict_traffic": 0.0,
}


def load_steampipe_tags(filepath: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse Steampipe JSON into structured asset dictionary
    Handles format: {"Resource Name": ["{key:value}", "{key:value}"]}
    """
    try:
        with open(filepath, 'r') as f:
            raw_data = json.load(f)
        
        parsed_assets = {}
        for resource_name, tag_list in raw_data.items():
            tags = {}
            for tag_item in tag_list:
                tag_item = tag_item.strip("{} ")
                if ":" in tag_item:
                    key, val = tag_item.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    
                    if val.lower() in ["true", "enabled", "yes"]:
                        val = True
                    elif val.lower() in ["false", "disabled", "no"]:
                        val = False
                    else:
                        try:
                            val = int(val.split()[0]) 
                        except:
                            pass
                    
                    tags[key] = val
            
            parsed_assets[resource_name.lower()] = tags
            parsed_assets[resource_name.replace("-", "_").lower()] = tags
            parsed_assets[resource_name.replace(" ", "_").lower()] = tags
            
        return parsed_assets
    except Exception as e:
        print(f"Warning: Steampipe tags not loaded: {e}")
        return {}

def extract_prowler_findings(filepath: str) -> List[Dict[str, Any]]:
    """Load Prowler findings from JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading Prowler findings: {e}")
        return []



def get_resource_context(resource_uid: str, resource_name: str, 
                        resource_type: str, prowler_metadata: Dict,finding : Dict,
                        steampipe_assets: Dict) -> Dict[str, Any]:
    """
    Unified context extractor merging Prowler + Steampipe metadata
    Returns: classification, public status, activity, retention, soft-delete
    """
    context = {
        "class": "Internal",
        "is_public": False,
        "is_active": True,
        "soft_delete": True,
        "retention": 30,
        "service": "unknown"
    }
    
    uid_lower = resource_uid.lower()
    name_lower = resource_name.lower()
    
    if any(x in uid_lower for x in ["iam", "role", "user", "group", "admin"]):
        context["service"] = "IAM"
        context["class"] = "Sensitive"
    elif any(x in uid_lower for x in ["s3", "storage", "bucket", "vault", "kms"]):
        context["service"] = "Storage"
        context["class"] = "Highly Sensitive"
    elif any(x in uid_lower for x in ["rds", "sql", "db", "postgresql", "mysql", "oracle", "mongodb"]):
        context["service"] = "Database"
        context["class"] = "Highly Sensitive"
    elif any(x in uid_lower for x in ["datasync", "data_factory", "migration", "transfer"]):
        context["service"] = "DataMovement"
        context["class"] = "Sensitive"
    elif any(x in uid_lower for x in ["cloudwatch", "monitor", "logs", "workspace", "splunk"]):
        context["service"] = "Monitoring"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["ec2", "instance", "vm", "compute", "eks", "ecs"]):
        context["service"] = "Compute"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["apigateway", "api_gateway"]):
        context["service"] = "APIGateway"
        context["class"] = "Sensitive"
    elif any(x in uid_lower for x in ["lambda", "function"]):
        context["service"] = "Lambda"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["firehose", "kinesis", "analytics"]):
        context["service"] = "Analytics"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["glue", "etl", "catalog"]):
        context["service"] = "ETL"
        context["class"] = "Sensitive"
    elif any(x in uid_lower for x in ["events", "eventbridge", "sns", "sqs", "notification"]):
        context["service"] = "EventBus"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["codebuild", "build", "pipeline", "codepipeline", "deploy"]):
        context["service"] = "CI/CD"
        context["class"] = "Internal"
    elif any(x in uid_lower for x in ["security_group", "sg-", "vpc", "subnet", "network"]):
        context["service"] = "Networking"
        context["class"] = "Sensitive"
    elif any(x in uid_lower for x in ["service_principal", "identity", "directory", "sso"]):
        context["service"] = "Identity"
        context["class"] = "Sensitive"
    elif "vault" in uid_lower:
        context["service"] = "KeyManagement"
        context["class"] = "Highly Sensitive"
    
    search_candidates = [
        resource_name.lower(),
        resource_name.replace("-", "_").lower(),
        resource_name.replace(" ", "_").lower(),
        resource_type.lower().replace("aws", "").replace("azure", "").strip(),
        context["service"].lower()
    ]
    
    asset_tags = {}
    for candidate in search_candidates:
        if candidate in steampipe_assets:
            asset_tags = steampipe_assets[candidate]
            break
    
    if asset_tags:
        for key, val in asset_tags.items():
            if "dataclassification" in key and isinstance(val, str):
                context["class"] = val.title()
            
            elif "public" in key and isinstance(val, bool):
                context["is_public"] = val
            
            elif "status" in key and isinstance(val, str):
                if val.lower() in ["disabled", "deleted", "failed", "inactive", "stopped"]:
                    context["is_active"] = False
            elif "account_enabled" in key and val == False:
                context["is_active"] = False
            
            elif "soft_delete" in key and isinstance(val, bool):
                context["soft_delete"] = val
            
            elif "retention" in key and isinstance(val, int):
                context["retention"] = val
    
    unmapped = finding.get("unmapped", {})
    categories = unmapped.get("categories", []) if isinstance(unmapped, dict) else []
    if "internet-exposed" in categories:
        context["is_public"] = True
    
    state = prowler_metadata.get("state", "")
    if state in ["stopped", "terminated", "deleted", "failed"]:
        context["is_active"] = False
    
    return context


def calculate_control_effectiveness(finding: Dict) -> float:
    """
    Map Prowler findings to control effectiveness scores
    """
    event_code = finding.get("metadata", {}).get("event_code", "")
    
    if event_code in FINDING_CONTROL_EFFECTIVENESS:
        return FINDING_CONTROL_EFFECTIVENESS[event_code]
    
    # Pattern-based matching
    if "mfa" in event_code.lower():
        return 0.0 if "FAIL" in finding.get("status_code", "") else CONTROL_EFFECTIVENESS["mfa_enabled"]
    
    if "encryption" in event_code.lower() or "kms" in event_code.lower():
        return 0.0 if "FAIL" in finding.get("status_code", "") else CONTROL_EFFECTIVENESS["encryption_enabled"]
    
    if "securitygroup" in event_code.lower():
        if "all_ports" in event_code:
            return 0.0
        return CONTROL_EFFECTIVENESS["security_group_restricted"]
    
    if "iam" in event_code.lower() and "privilege" in event_code.lower():
        return 0.0
    
    if "backup" in event_code.lower():
        return CONTROL_EFFECTIVENESS["backup_enabled"]
    
    if "logging" in event_code.lower() or "trail" in event_code.lower():
        return CONTROL_EFFECTIVENESS["logging_enabled"]
    
    severity = finding.get("severity", "High")
    if severity == "Critical":
        return 0.0
    elif severity == "High":
        return 0.10
    elif severity == "Medium":
        return 0.30
    elif severity == "Low":
        return 0.50
    
    return CONTROL_EFFECTIVENESS["default"]


def calculate_ale(loss_magnitude: float, threat_frequency: float, 
                 control_effectiveness: float) -> float:
    if loss_magnitude <= 0 or threat_frequency <= 0:
        return 0.0
    
    exposure = loss_magnitude * threat_frequency
    residual_risk = exposure * (1 - control_effectiveness)
    return max(residual_risk, 0.0)


def generate_risk_quantification_report(prowler_file: str, steampipe_file: str, 
                                       output_file: str = "risk_quantification_report.json"):
    """
    Generate GRC-ready risk quantification report
    """
    print("GRC RISK ENGINE - Multi-Cloud Risk Quantification")
    print("Methodology: FAIR (Factor Analysis of Information Risk)")
    
    steampipe_assets = load_steampipe_tags(steampipe_file)
    
    prowler_findings = extract_prowler_findings(prowler_file)
    
    risk_records = []
    
    for idx, finding in enumerate(prowler_findings, 1):
        try:
            if idx % 50 == 0:
                print(f"   → Processing {idx}/{len(prowler_findings)} findings...")
            
            resources = finding.get("resources", [])
            if not resources:
                continue
            
            resource = resources[0]
            r_uid = resource.get("uid", "unknown")
            r_name = resource.get("name", "")
            r_type = resource.get("type", "")
            r_metadata = resource.get("data", {}).get("metadata", {})
            
            if "<root_account>" in r_uid:
                r_name = "Root Account"
            
            context = get_resource_context(
                r_uid, r_name, r_type, r_metadata,finding, steampipe_assets
            )
            
            severity = finding.get("severity", "High")
            threat_frequency = THREAT_EVENT_FREQUENCY_DAYS.get(severity, 0.15)
            loss_magnitude = LOSS_MAGNITUDE_MAP_DOLLARS.get(context["class"], 10_000)
            control_effectiveness = calculate_control_effectiveness(finding)
            
            ale = calculate_ale(loss_magnitude, threat_frequency, control_effectiveness)
            
            unmapped = finding.get("unmapped", {})
            compliance = unmapped.get("compliance", {}) if isinstance(unmapped, dict) else {}
            frameworks = list(compliance.keys()) if isinstance(compliance, dict) else []
            
            nist_controls = []
            if isinstance(compliance, dict):
                nist_controls = compliance.get("NIST-CSF-2.0", []) or \
                              compliance.get("NIST-800-53-Revision-5", []) or \
                              compliance.get("NIST-800-53-Revision-4", []) or \
                              compliance.get("NIST-CSF-1.1", [])
            
            primary_control = nist_controls[0] if nist_controls else "SC-7"
            
            record = {
                "asset": r_name,
                "asset_uid": r_uid,
                "asset_type": r_type,
                "service": context["service"],
                "severity": severity,
                "classification": context["class"],
                "is_public": context["is_public"],
                "is_active": context["is_active"],
                "retention_days": context["retention"],
                "soft_delete": context["soft_delete"],
                "threat_frequency": threat_frequency,
                "loss_magnitude": loss_magnitude,
                "control_effectiveness": round(control_effectiveness, 2),
                "ale": round(ale, 2),
                "control": primary_control,
                "compliance": ", ".join(frameworks[:5]),
                "finding_code": finding.get("metadata", {}).get("event_code", ""),
                "risk_details": finding.get("risk_details", "")[:200],
                "remediation": finding.get("remediation", {}).get("desc", "")[:200],
                "region": resource.get("region", "unknown"),
                "cloud_provider": finding.get("cloud", {}).get("provider", "aws"),
                "account_id": finding.get("cloud", {}).get("account", {}).get("uid", "unknown"),
                "status": finding.get("status_code", "FAIL"),
                "created_time": finding.get("finding_info", {}).get("created_time_dt", "")
            }
            
            risk_records.append(record)
            
        except Exception as e:
            print(f"Skipping finding {idx}: {str(e)[:80]}...")
            continue
    
    df = pd.DataFrame(risk_records)
    
    summary = {
        "total_findings": len(risk_records),
        "total_ale": round(df["ale"].sum(), 2) if not df.empty else 0,
        "avg_ale": round(df["ale"].mean(), 2) if not df.empty else 0,
        "critical_count": int((df["severity"] == "Critical").sum()) if not df.empty else 0,
        "high_count": int((df["severity"] == "High").sum()) if not df.empty else 0,
        "medium_count": int((df["severity"] == "Medium").sum()) if not df.empty else 0,
        "low_count": int((df["severity"] == "Low").sum()) if not df.empty else 0,
        "generated_at": datetime.now().isoformat(),
        "methodology": "FAIR (Factor Analysis of Information Risk)",
        "sources": {
            "prowler_findings": len(prowler_findings),
            "steampipe_assets": len(steampipe_assets)
        }
    }
    
    print("\n" + "=" * 80)
    print("RISK QUANTIFICATION EXECUTIVE SUMMARY")
    print("=" * 80)
    print(f"Total Findings:     {summary['total_findings']:>6}")
    print(f"Critical:           {summary['critical_count']:>6}")
    print(f"High:               {summary['high_count']:>6}")
    print(f"Medium:             {summary['medium_count']:>6}")
    print(f"Low:                {summary['low_count']:>6}")
    print("-" * 80)
    print(f"Total ALE:          ${summary['total_ale']:>12,.2f}")
    print(f"Average ALE:        ${summary['avg_ale']:>12,.2f}")
    print("=" * 80)
    
    with open(output_file, "w") as f:
        json.dump(risk_records, f, indent=2, default=str)
    
    summary_file = output_file.replace(".json", "_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"\nMain report saved: {output_file}")
    print(f"Summary statistics: {summary_file}")
    
    return risk_records, summary

if __name__ == "__main__":
    generate_risk_quantification_report(
        prowler_file="filtered_prowler_findings1.json",
        steampipe_file="steampipe_tags1.json",
        output_file="risk_quantification_report.json"
    )
