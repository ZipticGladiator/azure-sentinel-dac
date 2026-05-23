resource "azurerm_sentinel_alert_rule_scheduled" "brute_force" {
  name                       = "84a7e94e-28d8-4f24-be02-b2da8774775d"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Multiple Failed Azure AD Logins"
  severity                   = "Medium"
  description                = "Detects multiple failed login attempts for a single user account."
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  query = <<KQL
SigninLogs
| where ResultType != "0"
| summarize FailedCount = count() by UserPrincipalName, IPAddress
| where FailedCount >= 5
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell" {
  name                       = "b6c9751e-3a7c-40ad-be23-5e72de7828c6"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Suspicious PowerShell Encoded Command"
  severity                   = "High"
  description                = "Detects execution of PowerShell with suspicious arguments such as encoded commands."
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1027"]

  query = <<KQL
SecurityEvent
| where EventID == 4688
| where ProcessName has "powershell.exe"
| where CommandLine has "-EncodedCommand" or CommandLine has "-enc" or CommandLine has "-e"
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "mfa_rejected" {
  name                       = "c1387d85-8422-4a00-ab62-b91c49dc7fc5"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "MFA Denied by User"
  severity                   = "Medium"
  description                = "Detects when a user explicitly denies an MFA request, which could indicate a compromised password."
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  query = <<KQL
SigninLogs
| where ResultType == "500121"
| extend StatusDetail = tostring(Status.additionalDetails)
| where StatusDetail has "MFA denied"
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}
