resource "aws_s3_bucket" "source" {
  bucket = "grc-backup-legacy-vault"
  tags = { "DataClassification" = "Highly Sensitive" }
}

resource "aws_s3_bucket_public_access_block" "source_pab" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source_sse" {
  bucket = aws_s3_bucket.source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "grc_kv" {
  name                     = var.key_vault_name
  location                 = var.azure_region
  resource_group_name      = var.az_res_group
  tenant_id                = data.azurerm_client_config.current.tenant_id
  sku_name                 = "standard"
  purge_protection_enabled = false

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "Set", "List", "Delete","Purge"]
  }
}

resource "azurerm_storage_account" "dest_storage" {
  name                     = "grcmigrationdst"
  resource_group_name      = var.az_res_group
  location                 = var.azure_region
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2" 
}

resource "azurerm_storage_container" "dest_container" {
  name                  = "migration-landing-container"
  storage_account_name = azurerm_storage_account.dest_storage.name
  container_access_type = "private"
}

resource "azurerm_mssql_server" "dest_sql" {
  name                         = "grc-target-sql-server"
  resource_group_name          = var.az_res_group
  location                     = var.azure_region
  version                      = "12.0"
  administrator_login          = "adminuser"
  administrator_login_password = var.azure_db_password
  minimum_tls_version          = "1.2"
}

resource "azurerm_mssql_database" "dest_db" {
  name      = "targetdb"
  server_id = azurerm_mssql_server.dest_sql.id
  sku_name  = "Basic"
}

resource "aws_db_instance" "source_db" {
  allocated_storage   = 20
  engine              = "sqlserver-ex" 
  instance_class      = "db.t3.micro"  
  username            = "adminuser"
  password            = var.aws_db_password
  skip_final_snapshot = true
  storage_encrypted   = true
  publicly_accessible = true  
  port                = var.aws_db_port
}





resource "azurerm_key_vault_secret" "storage_account_key" {
  name         = "storage-account-key"
  value        = azurerm_storage_account.dest_storage.primary_access_key
  key_vault_id = azurerm_key_vault.grc_kv.id
  depends_on   = [azurerm_storage_account.dest_storage]
}


resource "aws_iam_role" "datasync_role" {
  name = "DataSyncMigrationRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = { Service = "datasync.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "datasync_s3_policy" {
  role = aws_iam_role.datasync_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
        Resource = [aws_s3_bucket.source.arn, "${aws_s3_bucket.source.arn}/*"]
      },
      {
        Effect = "Allow",
        Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_datasync_location_s3" "s3_source" {
  s3_bucket_arn = aws_s3_bucket.source.arn
  subdirectory  = "/"
  s3_config {
    bucket_access_role_arn = aws_iam_role.datasync_role.arn
  }
}

data "azurerm_storage_account_sas" "datasync_sas" {
  connection_string = azurerm_storage_account.dest_storage.primary_connection_string
  https_only        = true 
  resource_types {
  service   = true
  container = true
  object    = true
 }   
  services {
    blob = true
    queue = false
    table = false
    file = false
  }
  start  = timeadd(timestamp(), "-15m")
  expiry = timeadd(timestamp(), "24h")
  permissions {
    read = true
    write = true
    delete = true
    list = true
    add = true
    filter = false  
    create = false 
    tag = false
    update = true
    process = false
  }
}

resource "aws_datasync_agent" "agent" {
  count          = var.create_datasync_agent ? 1 : 0
  ip_address     = var.agent_ip_address
  name           = "grc-datasync-agent"
}

resource "aws_datasync_location_azure_blob" "azure_dest" {
  agent_arns            = [aws_datasync_agent.agent[0].arn]
  authentication_type   = "SAS"
  container_url         = "https://${azurerm_storage_account.dest_storage.name}.blob.core.windows.net/${azurerm_storage_container.dest_container.name}"
  
  sas_configuration {
    token = data.azurerm_storage_account_sas.datasync_sas.sas
  }

  depends_on = [aws_datasync_agent.agent]
}

resource "aws_cloudwatch_log_group" "datasync_logs" {
  name              = "/aws/datasync/s3-to-blob-sync"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_resource_policy" "datasync_policy" {
  policy_name = "DataSyncLoggingPolicy"
  policy_document = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "DataSyncLogsToCloudWatch",
      Effect = "Allow",
      Principal = { Service = "datasync.amazonaws.com" },
      Action = [
        "logs:PutLogEvents",
        "logs:CreateLogStream"
      ],
      Resource = "${aws_cloudwatch_log_group.datasync_logs.arn}:*"
    }]
  })
}


resource "aws_datasync_task" "s3_to_blob" {
  name                     = "GRC-s3-to-azure-sync"
  source_location_arn      = aws_datasync_location_s3.s3_source.arn
  destination_location_arn = aws_datasync_location_azure_blob.azure_dest.arn
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.datasync_logs.arn

  options {
    verify_mode = "ONLY_FILES_TRANSFERRED"
    log_level   = "TRANSFER"
    uid              = "NONE"
    gid              = "NONE"
    posix_permissions = "NONE"
    preserve_devices = "NONE"
  }
  depends_on = [aws_cloudwatch_log_group.datasync_logs ]
}


resource "azurerm_data_factory" "grc_adf" {
  name                = "grcmigrationsync${substr(uuid(), 0, 6)}" 
  location            = var.azure_region
  resource_group_name = var.az_res_group
}

resource "azurerm_data_factory_linked_service_sql_server" "rds_source" {
  name              = "rds-sql-source"
  data_factory_id   = azurerm_data_factory.grc_adf.id
  connection_string = "Server=${aws_db_instance.source_db.address},${var.aws_db_port};Database=legacy_db;User Id=adminuser;Password=${var.aws_db_password};"
}

resource "azurerm_data_factory_linked_service_azure_sql_database" "sql_dest" {
  name              = "azure-sql-destination"
  data_factory_id   = azurerm_data_factory.grc_adf.id
  connection_string = "Server=tcp:${azurerm_mssql_server.dest_sql.fully_qualified_domain_name},1433;Initial Catalog=targetdb;User ID=adminuser;Password=${var.azure_db_password};"
}

resource "azurerm_data_factory_dataset_sql_server_table" "rds_ds" {
  name                = "RDSSourceTable"
  data_factory_id     = azurerm_data_factory.grc_adf.id
  linked_service_name = azurerm_data_factory_linked_service_sql_server.rds_source.name
  table_name          = "dbo.SourceTable" 
}

resource "azurerm_data_factory_dataset_azure_sql_table" "sql_dest_ds" {
  name                = "AzureSQLDestTable"
  linked_service_id   = azurerm_data_factory_linked_service_azure_sql_database.sql_dest.id
  data_factory_id     = azurerm_data_factory.grc_adf.id
  
  schema_column {
    name          = "dbo"
    type          = "String"
    description   = "Target table schema"
  }
}

resource "azurerm_data_factory_pipeline" "db_migration" {
  name            = "RDS-to-azure-sql-pipeline"
  data_factory_id = azurerm_data_factory.grc_adf.id
  
  activities_json = <<JSON
  [
    {
      "name": "CopyFromRDSToAzureSQL",
      "type": "Copy",
      "typeProperties": {
        "source": { "type": "SqlSource" },
        "sink": { "type": "AzureSqlSink", "writeBatchSize": 10000 },
        "enableStaging": false
      },
      "inputs": [ { "referenceName": "RDSSourceTable", "type": "DatasetReference" } ], 
      "outputs": [ { "referenceName": "AzureSQLDestTable", "type": "DatasetReference" } ]
    }
  ]
  JSON
  
  depends_on = [
    azurerm_data_factory_dataset_azure_sql_table.sql_dest_ds,
    azurerm_data_factory_dataset_sql_server_table.rds_ds
  ]
}

resource "azurerm_log_analytics_workspace" "grc_logs" {
  name                = "grc-migration-logs"
  location            = var.azure_region
  resource_group_name = var.az_res_group
  sku                 = "PerGB2018"
}

resource "azurerm_monitor_diagnostic_setting" "adf_logging" {
  name                       = "ADFToLogAnalytics"
  target_resource_id         = azurerm_data_factory.grc_adf.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc_logs.id

  enabled_log {
    category = "PipelineRuns"
  }

  enabled_log {
    category = "ActivityRuns"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
  depends_on = [ azurerm_data_factory.grc_adf,azurerm_log_analytics_workspace.grc_logs ]
}