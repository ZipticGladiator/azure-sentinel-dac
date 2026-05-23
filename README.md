# Azure Sentinel Detection-as-Code

This repository contains a Terraform-based implementation for provisioning Microsoft Sentinel (Azure Sentinel) and deploying custom detection rules mapped to the MITRE ATT&CK framework. It demonstrates a complete "Detection-as-Code" (DaC) workflow.

## Overview

Modern Security Operations Centers (SOCs) require scalable, repeatable, and version-controlled environments. By using Infrastructure as Code (IaC) to deploy the SIEM and Detection-as-Code for the alerting logic, this project ensures that security monitoring is reliable and explicitly aligned to known threat models.

### Architecture

1. **Log Analytics Workspace**: The foundational data lake where all security logs and telemetry are ingested.
2. **Microsoft Sentinel**: Onboarded onto the Log Analytics Workspace to provide SIEM and SOAR capabilities.
3. **Scheduled Alert Rules**: Custom Kusto Query Language (KQL) detection rules deployed natively through Terraform.

## Detection Coverage (MITRE ATT&CK)

The included detection rules (`rules.tf`) are mapped to the MITRE ATT&CK framework to ensure comprehensive threat coverage:

| Rule Name | Tactics | Techniques | Description |
|-----------|---------|------------|-------------|
| **Multiple Failed Azure AD Logins** | Credential Access | T1110 (Brute Force) | Detects 5+ failed login attempts from a single user account indicating potential brute-force activity. |
| **Suspicious PowerShell Encoded Command** | Execution, Defense Evasion | T1059, T1027 | Detects execution of `powershell.exe` with arguments indicative of obfuscated or encoded commands (`-EncodedCommand`, `-enc`, etc.). |
| **MFA Denied by User** | Credential Access | T1110 (Brute Force) | Alerts when a legitimate user denies an MFA push notification, which often indicates a compromised primary password. |

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) (>= 1.0)
- An active Azure Subscription
- Azure CLI (authenticated via `az login`)

## Deployment

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd azure-sentinel-dac
   ```

2. Initialize Terraform to download the required `azurerm` provider:
   ```bash
   terraform init
   ```

3. Review the execution plan to see the resources that will be created:
   ```bash
   terraform plan
   ```

4. Apply the configuration to your Azure environment:
   ```bash
   terraform apply
   ```

## Repository Structure

- `main.tf` - Provisions the Resource Group, Log Analytics Workspace, and Sentinel solution.
- `rules.tf` - Contains the KQL-based Sentinel scheduled alert rules.
- `variables.tf` - Defines configurable parameters (e.g., Region, Workspace Name).
- `providers.tf` - Azure provider configurations.

## Future Enhancements
- Integration of CI/CD pipelines (e.g., GitHub Actions) to automatically validate and deploy rule updates.
- Addition of data connectors (e.g., Azure Active Directory, Office 365) via Terraform.
- Implementation of automated response playbooks using Azure Logic Apps.
