variable "aws_region"{
  default = "ap-east-1"
  type = string 
}

variable "azure_region" {
  default = "EastAsia"
  type = string 
}

variable "azure_db_password" {
  description = "sensitive password for azure sql"
  type=string 
  sensitive = true 
}
variable "aws_db_password" {
  description = "sensitive password for aws RDS"
  type=string 
  sensitive = true 
}
variable "az_res_group" {
  default = "Grc-backup"
  type = string 
}

# Added variables to avoid hardcoding DB ports in multiple places
variable "aws_db_port" {
  description = "AWS RDS SQL Server port"
  type = number
  default = 1433
}
variable "azure_sql_port" {
  description = "Azure SQL Server port"
  type = number
  default = 1433
}

variable "key_vault_name" {
  description = "Name for the Azure Key Vault to store secrets"
  type        = string
  default     = "grc-keyvault123"
}

variable "create_datasync_agent" {
  description = "Whether to create an AWS DataSync agent resource (requires activation key)"
  type        = bool
  default     = true
}

variable "datasync_agent_activation_key" {
  description = "Activation key for the DataSync agent (sensitive). Obtain from AWS DataSync agent appliance setup."
  type        = string
  sensitive   = true
  /*
    You need to obtain the Activation Key by setting up an AWS DataSync Agent appliance. Follow these steps for a VM datasync agent based approach 
    (Disclaimer: For dev environment only,not secure for production environment):

    1) Deploy the Agent: Launch an EC2 instance using the official AWS DataSync AMI (search for "DataSync" in the AMI Marketplace).

    2) Ensure Port 80 is Open: The Security Group for this EC2 instance must allow inbound HTTP (Port 80 and note that the EC2 instance should be in running state) from the machine  
       where you are running Terraform.

    3) Fetch the Key: Use a simple curl command from your local terminal to the Agent's IP address:

    Bash

    curl -vvv "http://<AGENT_IP_ADDRESS>/?gatewayType=SYNC&activationRegion=<YOUR_REGION>&no_redirect"
    The Result: It will return a string like XXXXX-XXXXX-XXXXX-XXXXX-XXXXX at the end. This is your Activation Key

  */
  default     = ""
}

variable "agent_ip_address"{
  sensitive = true 
  type = string 
}