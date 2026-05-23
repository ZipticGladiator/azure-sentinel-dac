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

resource "azurerm_sentinel_alert_rule_scheduled" "impossible_travel" {
  name                       = "d2498e96-9533-4f3a-b812-c2cb97886c71"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Impossible Travel Activity"
  severity                   = "High"
  description                = "Detects when the same user logs in from two geographically distant locations within an impossibly short timeframe."
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]

  query = <<KQL
SigninLogs
| where ResultType == 0
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| summarize dcount(Country) by UserPrincipalName, bin(TimeGenerated, 1h)
| where dcount_Country > 1
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_inbox_rule" {
  name                       = "e3509fa7-0644-405b-c923-d3dc08997d82"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Suspicious Inbox Forwarding Rule Created"
  severity                   = "Medium"
  description                = "Detects when a user creates an email rule that forwards emails containing financial keywords or moves them to deleted items."
  tactics                    = ["Collection"]
  techniques                 = ["T1114"]

  query = <<KQL
OfficeActivity
| where RecordType == "ExchangeItem" and Operation in ("New-InboxRule", "Set-InboxRule")
| extend Parameters = tostring(Parameters)
| where Parameters has_any ("invoice", "payment", "bank", "wire", "transfer") or Parameters has "DeleteMessage"
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "new_global_admin" {
  name                       = "f461b0b8-1755-516c-da34-e4ed190a8e93"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "New Global Administrator Role Assigned"
  severity                   = "High"
  description                = "Triggers a high-severity alert whenever a user is added to the Global Administrator or Privileged Role Administrator groups."
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1078", "T1098"]

  query = <<KQL
AuditLogs
| where Category == "RoleManagement"
| where ActivityDisplayName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName in ("Global Administrator", "Privileged Role Administrator")
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "mass_file_deletion" {
  name                       = "0572c1c9-2866-627d-eb45-f5fe2a1b9fa4"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Mass File Deletion in SharePoint/OneDrive"
  severity                   = "Medium"
  description                = "Detects if a user deletes an unusually high volume of files from SharePoint or OneDrive within a short window."
  tactics                    = ["Impact"]
  techniques                 = ["T1485"]

  query = <<KQL
OfficeActivity
| where RecordType in ("SharePointFileOperation", "OneDrive")
| where Operation == "FileDeleted"
| summarize DeletedCount = count() by UserId, ClientIP, bin(TimeGenerated, 15m)
| where DeletedCount > 50
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}

resource "azurerm_sentinel_alert_rule_scheduled" "malicious_ip_login" {
  name                       = "1683d2da-3977-738e-fc56-060f3b2ca0b5"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  display_name               = "Sign-in from Malicious IP or Tor Network"
  severity                   = "High"
  description                = "Identifies traffic originating from known Tor exit nodes or anonymous proxies."
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1190"]

  query = <<KQL
SigninLogs
| where ResultType == 0
| extend NetworkLocationDetails = tostring(LocationDetails)
| where NetworkLocationDetails has "tor" or NetworkLocationDetails has "anonymous proxy"
KQL

  query_frequency     = "PT1H"
  query_period        = "PT1H"
  trigger_operator    = "GreaterThan"
  trigger_threshold   = 0
  suppression_enabled = false
}
