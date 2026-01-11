import psycopg2
import json,time

def fetch_multicloud_tags():
    connection_params = {
        "database": "steampipe",
        "user": "steampipe",
        "password": "", 
        "host": "127.0.0.1",
        "port": "9193"
    }

    try:
        conn = psycopg2.connect(**connection_params)
        cursor = conn.cursor()

        result = {}

        queries = {
            "AWS S3 Buckets": "SELECT name, tags FROM aws_s3_bucket WHERE name = 'grc-backup-legacy-vault';",
            "AWS RDS Instances": "SELECT db_instance_identifier,publicly_accessible FROM aws_rds_db_instance;", 
            "AWS CloudWatch Group": "SELECT arn, retention_in_days FROM aws_cloudwatch_log_group;",
            "AWS IAM User":"SELECT arn,attached_policy_arns,create_date FROM aws_iam_user WHERE arn = 'arn:aws:iam::869935106430:user/Aws_backup_user';",
            "AWS DataSync Task":"SELECT arn, status, source_location_arn, destination_location_arn FROM aws_datasync_task;",

            "Azure Monitor":"SELECT id, retention_in_days FROM azure_log_analytics_workspace;",
            "Azure Service Principal":"SELECT display_name, app_id, account_enabled, service_principal_type FROM azuread_service_principal WHERE app_id = '1a91fb94-6db9-4906-a3a2-bdb94ed93a78';",
            "Azure Data Factory":"SELECT name, resource_group, provisioning_state, public_network_access FROM azure_data_factory;",
            "Azure Storage Accounts": "SELECT name, allow_blob_public_access,blob_soft_delete_enabled FROM azure_storage_account WHERE name = 'grcmigrationdst';",
            "Azure MSSQL Servers": "SELECT name, public_network_access FROM azure_sql_server WHERE name = 'grc-target-sql-server';"
        }


        for resource_type, sql in queries.items():
            cursor.execute(sql)
            results = cursor.fetchall()
            
            print(f"[{resource_type}]")
            if not results:
                print("  No resource found.") #used for error handling 
            for row in results:
                name, tags = row[0],[str(item) for item in row[1:]]
                result[name] = tags 

        with open("steampipe_tags1.json","w") as f:
            json.dump(result,f,indent=4)

    except Exception as e:
        print(f"Error connecting to Steampipe: {e}")
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    fetch_multicloud_tags()