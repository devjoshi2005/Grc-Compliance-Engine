
output "aws_s3_source_bucket" {
  description = "The source S3 bucket name"
  value       = aws_s3_bucket.source.id
}

output "aws_rds_source_endpoint" {
  description = "The connection endpoint for the legacy RDS instance"
  value       = aws_db_instance.source_db.endpoint
}

output "aws_datasync_task_arn" {
  description = "ARN of the DataSync task (use this to trigger sync via CLI/Python)"
  value       = aws_datasync_task.s3_to_blob.arn
}

output "aws_cloudwatch_log_group" {
  description = "The Log Group for DataSync transmission audits"
  value       = aws_cloudwatch_log_group.datasync_logs.name
}


output "azure_storage_account_name" {
  description = "Destination Storage Account for unstructured data"
  value       = azurerm_storage_account.dest_storage.name
}

output "azure_sql_server_fqdn" {
  description = "The FQDN of the destination Azure SQL Server"
  value       = azurerm_mssql_server.dest_sql.fully_qualified_domain_name
}

output "azure_sql_database_name" {
  description = "The target database for ADF ingestion"
  value       = azurerm_mssql_database.dest_db.name
}

output "azure_key_vault_uri" {
  description = "The URI of the Key Vault for secret retrieval"
  value       = azurerm_key_vault.grc_kv.vault_uri
}

output "azure_data_factory_name" {
  description = "The Data Factory instance orchestrating the DB move"
  value       = azurerm_data_factory.grc_adf.name
}

output "azure_log_analytics_workspace_id" {
  description = "The ID of the workspace containing ADF and SQL audit logs"
  value       = azurerm_log_analytics_workspace.grc_logs.workspace_id
}


output "datasync_agent_arn" {
  description = "ARN of the activated DataSync Agent (must be active for sync to work)"
  value       = var.create_datasync_agent ? aws_datasync_agent.agent[0].arn : "Not Created"
}