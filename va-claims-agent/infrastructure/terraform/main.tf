terraform {
  required_version = ">= 1.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "rg-va-claims-dev"
    storage_account_name = "vaclaimstfstate"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Data source for current subscription
data "azurerm_client_config" "current" {}

# Resource Group (already exists, import it)
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    environment = var.environment
    project     = "va-claims-agent"
  }
}

# PostgreSQL Flexible Server with pgvector
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "psql-vaclaims-${var.environment}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "15"
  administrator_login    = var.db_admin_username
  administrator_password = var.db_admin_password
  storage_mb             = 32768
  sku_name               = "B_Standard_B1ms"
  zone                   = "1"

  tags = {
    environment = var.environment
  }
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "vaclaims" {
  name      = "vaclaims"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# Enable pgvector extension
resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "vector,uuid-ossp,pg_trgm"
}

# Firewall rule for Azure services
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Storage Account for documents
resource "azurerm_storage_account" "documents" {
  name                     = "stvaclaimsdocs${var.environment}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }
  }

  tags = {
    environment = var.environment
  }
}

# Blob containers
resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.documents.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "processed" {
  name                  = "processed"
  storage_account_name  = azurerm_storage_account.documents.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "forms" {
  name                  = "forms"
  storage_account_name  = azurerm_storage_account.documents.name
  container_access_type = "private"
}

# Service Bus Namespace
resource "azurerm_servicebus_namespace" "main" {
  name                = "sb-vaclaims-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard"

  tags = {
    environment = var.environment
  }
}

# Service Bus Queues
resource "azurerm_servicebus_queue" "document_processing" {
  name         = "document-processing"
  namespace_id = azurerm_servicebus_namespace.main.id

  max_delivery_count        = 10
  lock_duration             = "PT5M"
  max_size_in_megabytes     = 1024
  enable_partitioning       = false
  dead_lettering_on_message_expiration = true
}

resource "azurerm_servicebus_queue" "claim_analysis" {
  name         = "claim-analysis"
  namespace_id = azurerm_servicebus_namespace.main.id

  max_delivery_count        = 10
  lock_duration             = "PT5M"
  max_size_in_megabytes     = 1024
  enable_partitioning       = false
  dead_lettering_on_message_expiration = true
}

resource "azurerm_servicebus_queue" "forms_generation" {
  name         = "forms-generation"
  namespace_id = azurerm_servicebus_namespace.main.id

  max_delivery_count        = 10
  lock_duration             = "PT5M"
  max_size_in_megabytes     = 1024
  enable_partitioning       = false
  dead_lettering_on_message_expiration = true
}

# Key Vault for secrets
resource "azurerm_key_vault" "main" {
  name                        = "kv-vaclaims-${var.environment}"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Create", "Delete", "Update",
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete",
    ]
  }

  tags = {
    environment = var.environment
  }
}

# Container Registry
resource "azurerm_container_registry" "main" {
  name                = "crvaclaims${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = {
    environment = var.environment
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-vaclaims-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    environment = var.environment
  }
}

# Container Apps Environment
resource "azurerm_container_app_environment" "main" {
  name                       = "cae-vaclaims-${var.environment}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  tags = {
    environment = var.environment
  }
}

# Container App - API
resource "azurerm_container_app" "api" {
  name                         = "ca-vaclaims-api"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    container {
      name   = "api"
      image  = "${azurerm_container_registry.main.login_server}/vaclaims-api:latest"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }

      env {
        name        = "ANTHROPIC_API_KEY"
        secret_name = "anthropic-api-key"
      }

      env {
        name  = "AZURE_STORAGE_ACCOUNT"
        value = azurerm_storage_account.documents.name
      }
    }

    min_replicas = 1
    max_replicas = 5
  }

  secret {
    name  = "database-url"
    value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/vaclaims?sslmode=require"
  }

  secret {
    name  = "anthropic-api-key"
    value = var.anthropic_api_key
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "registry-password"
  }

  secret {
    name  = "registry-password"
    value = azurerm_container_registry.main.admin_password
  }

  tags = {
    environment = var.environment
  }
}

# Container App - Web
resource "azurerm_container_app" "web" {
  name                         = "ca-vaclaims-web"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    container {
      name   = "web"
      image  = "${azurerm_container_registry.main.login_server}/vaclaims-web:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      env {
        name  = "NEXT_PUBLIC_API_URL"
        value = "https://${azurerm_container_app.api.ingress[0].fqdn}"
      }
    }

    min_replicas = 1
    max_replicas = 3
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "registry-password"
  }

  secret {
    name  = "registry-password"
    value = azurerm_container_registry.main.admin_password
  }

  tags = {
    environment = var.environment
  }
}

# Container App - Worker
resource "azurerm_container_app" "worker" {
  name                         = "ca-vaclaims-worker"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    container {
      name   = "worker"
      image  = "${azurerm_container_registry.main.login_server}/vaclaims-worker:latest"
      cpu    = 1.0
      memory = "2Gi"

      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }

      env {
        name        = "ANTHROPIC_API_KEY"
        secret_name = "anthropic-api-key"
      }

      env {
        name        = "AZURE_SERVICE_BUS_CONNECTION_STRING"
        secret_name = "servicebus-connection"
      }
    }

    min_replicas = 1
    max_replicas = 10
  }

  secret {
    name  = "database-url"
    value = "postgresql://${var.db_admin_username}:${var.db_admin_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/vaclaims?sslmode=require"
  }

  secret {
    name  = "anthropic-api-key"
    value = var.anthropic_api_key
  }

  secret {
    name  = "servicebus-connection"
    value = azurerm_servicebus_namespace.main.default_primary_connection_string
  }

  secret {
    name  = "registry-password"
    value = azurerm_container_registry.main.admin_password
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "registry-password"
  }

  tags = {
    environment = var.environment
  }
}

# Azure Cognitive Services for OCR
resource "azurerm_cognitive_account" "document_intelligence" {
  name                = "cog-vaclaims-docint-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "FormRecognizer"
  sku_name            = "S0"

  tags = {
    environment = var.environment
  }
}
