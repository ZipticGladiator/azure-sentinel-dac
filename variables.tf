variable "location" {
  type        = string
  description = "The Azure region where resources will be created"
  default     = "South Africa North"
}

variable "resource_group_name" {
  type        = string
  description = "The name of the Resource Group"
  default     = "rg-sentinel-southafrica"
}

variable "log_analytics_workspace_name" {
  type        = string
  description = "The name of the Log Analytics Workspace"
  default     = "law-sentinel-southafrica"
}
