# Azure Front Door Ruleset Manager

PowerShell script to extract, duplicate, and manage Azure Front Door Standard/Premium rulesets.

## Overview

This script connects to an Azure Front Door Standard/Premium profile and extracts all rulesets with their rules, conditions, and actions. It generates a complete ARM template that can be deployed to create duplicate rulesets with different names.

**Key Features:**
- Extracts complete ruleset configurations including all rules
- Generates deployable ARM templates with proper dependencies
- Supports automatic ruleset renaming via mapping files
- Allows selective exclusion of rulesets (useful to avoid duplicates)
- Includes cleanup mode to safely remove deployed rulesets

**Two Modes:**
- **Extract Mode (default)**: Reads existing rulesets and generates ARM templates for deployment
- **Cleanup Mode**: Deletes rulesets from Azure Front Door based on mapping file (requires confirmation)

## Prerequisites

- PowerShell 7.0+
- Azure PowerShell module: `Az.Cdn` 
- Authenticated Azure session: `Connect-AzAccount`
- Permissions: Reader access for extract mode, Contributor access for cleanup mode

## Usage & Examples

### Mapping File Format
Create a text file with one mapping per line to rename rulesets:
```text
# Format: OldRuleSetName=NewRuleSetName
Azure20Roma80=NEWAzure20Roma80
Azure10Roma90=NEWAzure10Roma90
Bilanciamento1=NEWBilanciamento1
```

### Basic Workflow
```powershell
# 1. Extract with renaming and save to file
.\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -RuleSetMappingFile ".\mapping.txt" -OutputPath ".\rulesets.json"

# 2. Deploy the template (preview first with -WhatIf)
New-AzResourceGroupDeployment -ResourceGroupName "myRG" -TemplateFile ".\rulesets.json" -WhatIf
New-AzResourceGroupDeployment -ResourceGroupName "myRG" -TemplateFile ".\rulesets.json"

# 3. Cleanup if needed (requires typing 'DELETE' to confirm)
.\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -RuleSetMappingFile ".\mapping.txt" -CleanupMode
```

### Common Scenarios

**Environment Promotion** - Duplicate production to staging:
```powershell
.\update-afdjsonrulesets.ps1 -FrontDoorName "prod-afd" -ResourceGroupName "prod-rg" -RuleSetMappingFile ".\prod-to-staging.txt" -OutputPath ".\staging-rulesets.json"
```

**Backup** - Create timestamped backup:
```powershell
.\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -OutputPath ".\backup-$(Get-Date -Format 'yyyyMMdd').json"
```

**Testing** - Create test copies excluding legacy rulesets:
```powershell
.\update-afdjsonrulesets.ps1 -FrontDoorName "prod-afd" -ResourceGroupName "prod-rg" -RuleSetMappingFile ".\prod-to-test.txt" -ExcludeRuleSets @("LEGACY*") -OutputPath ".\test-rulesets.json"
```

**Cleanup** - Remove deployed rulesets:
```powershell
.\update-afdjsonrulesets.ps1 -FrontDoorName "test-afd" -ResourceGroupName "test-rg" -RuleSetMappingFile ".\test-mapping.txt" -CleanupMode
```
**Note**: Cleanup mode deletes rulesets using the NEW names (right side of `=` in mapping file).