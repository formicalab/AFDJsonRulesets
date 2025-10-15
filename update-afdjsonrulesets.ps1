#Requires -PSEdition Core
<#
.SYNOPSIS
    Extracts Azure Front Door Standard/Premium rulesets and generates deployable ARM template JSON.

.DESCRIPTION
    This script retrieves an Azure Front Door Standard/Premium profile, extracts all rulesets
    and their rules, then generates a complete ARM template for deploying duplicate rulesets.
    The script supports automatic ruleset renaming via mapping files, exclusion of specific
    rulesets, and generates a deployable JSON template with proper dependencies and ARM syntax.
    
    Key Features:
    - Extracts complete ruleset configurations including all rules, conditions, and actions
    - Automatically converts Azure PowerShell objects to ARM template format
    - Supports ruleset renaming through mapping files for safe deployment
    - Allows exclusion of specific rulesets (useful to avoid duplicates)
    - Generates ARM template with proper resource dependencies
    - Provides detailed validation and deployment guidance

.PARAMETER FrontDoorName
    The name of the Azure Front Door Standard/Premium profile.

.PARAMETER ResourceGroupName
    The name of the resource group containing the Front Door profile.

.PARAMETER SubscriptionName
    Optional. The name of the Azure subscription. If not specified, uses the current context.

.PARAMETER OutputPath
    Optional. The path where the JSON file will be saved. If not specified, outputs to console.

.PARAMETER RuleSetMappingFile
    Optional. Path to a text file containing ruleset name mappings (one per line: OldName=NewName).
    When provided, rulesets will be automatically renamed in the output JSON.

.PARAMETER ExcludeRuleSets
    Optional. Array of ruleset names to exclude from the export.
    Useful to avoid duplicates when re-exporting after previous deployments.

.PARAMETER CleanupMode
    Optional. Switch to enable cleanup mode. When specified, the script will DELETE rulesets
    from Azure Front Door based on the NEW names specified in the RuleSetMappingFile.
    Requires RuleSetMappingFile parameter. Prompts for confirmation before deletion.
    Use this to remove previously deployed rulesets.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG"
    
    Extracts all rulesets from the specified Front Door profile and outputs the ARM template JSON to console.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -OutputPath ".\rulesets.json"
    
    Extracts rulesets and saves the ARM template to a JSON file.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -SubscriptionName "Production"
    
    Extracts rulesets from a specific Azure subscription context.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -RuleSetMappingFile ".\Tests\ruleset-mapping.txt" -OutputPath ".\rulesets.json"
    
    Extracts rulesets and automatically renames them according to the mapping file before generating the ARM template.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -ExcludeRuleSets @("NEW*") -OutputPath ".\rulesets.json"
    
    Extracts rulesets but excludes any ruleset whose name starts with "NEW" (useful to avoid duplicates).

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -ExcludeRuleSets @("NEW*", "TestRuleset") -RuleSetMappingFile ".\mapping.txt" -OutputPath ".\production-rulesets.json"
    
    Advanced usage: Excludes specific rulesets by name and pattern, applies name mappings, and saves to a specific file.

.EXAMPLE
    .\update-afdjsonrulesets.ps1 -FrontDoorName "myafd" -ResourceGroupName "myRG" -RuleSetMappingFile ".\Tests\ruleset-mapping.txt" -CleanupMode
    
    Cleanup mode: Removes rulesets from Azure Front Door based on the NEW names in the mapping file.
    Prompts for confirmation before deletion. Use this to clean up previously deployed rulesets.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Specify the Azure Front Door profile name')]
    [string]$FrontDoorName,

    [Parameter(Mandatory = $true, HelpMessage = 'Specify the resource group name')]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false, HelpMessage = 'Specify the subscription name (optional, uses current context if not specified)')]
    [string]$SubscriptionName,

    [Parameter(Mandatory = $false, HelpMessage = 'Specify the output file path for the JSON (optional, outputs to console if not specified)')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Specify a mapping file for renaming rulesets (format: OldName=NewName)')]
    [string]$RuleSetMappingFile,

    [Parameter(Mandatory = $false, HelpMessage = 'Array of ruleset names or patterns to exclude (supports wildcards)')]
    [string[]]$ExcludeRuleSets,

    [Parameter(Mandatory = $false, HelpMessage = 'Cleanup mode: removes rulesets specified in the mapping file (uses new names from mapping)')]
    [switch]$CleanupMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    # Validate parameters for cleanup mode
    if ($CleanupMode -and -not $RuleSetMappingFile) {
        Write-Host "❌ " -NoNewline -ForegroundColor Red
        Write-Error "CleanupMode requires RuleSetMappingFile parameter to be specified"
    }

    # Load ruleset mapping if provided
    $ruleSetMapping = @{}
    if ($RuleSetMappingFile) {
        if (-not (Test-Path $RuleSetMappingFile)) {
            Write-Host "❌ " -NoNewline -ForegroundColor Red
            Write-Error "Mapping file not found: $RuleSetMappingFile"
        }
        
        Write-Host "Loading ruleset mapping from: " -NoNewline
        Write-Host $RuleSetMappingFile -ForegroundColor Cyan
        
        $mappingLines = Get-Content $RuleSetMappingFile -ErrorAction Stop
        foreach ($line in $mappingLines) {
            $line = $line.Trim()
            if ($line -and -not $line.StartsWith('#')) {
                if ($line -match '^(.+?)=(.+)$') {
                    $oldName = $matches[1].Trim()
                    $newName = $matches[2].Trim()
                    $ruleSetMapping[$oldName] = $newName
                    Write-Host "  📍 " -NoNewline
                    Write-Host $oldName -ForegroundColor Cyan -NoNewline
                    Write-Host " → " -NoNewline
                    Write-Host $newName -ForegroundColor Cyan
                }
            }
        }
        
        Write-Host "✅ Loaded " -NoNewline -ForegroundColor Green
        Write-Host $ruleSetMapping.Count -ForegroundColor Cyan -NoNewline
        Write-Host " mapping(s)`n"
    }
    
    # Set subscription context if specified
    if ($SubscriptionName) {
        Write-Host "⚙️  Setting subscription context to: " -NoNewline
        Write-Host $SubscriptionName -ForegroundColor Cyan
        Set-AzContext -SubscriptionName $SubscriptionName -ErrorAction Stop | Out-Null
    }

    # Get current subscription for display
    $currentContext = Get-AzContext
    Write-Host "Working in subscription: " -NoNewline
    Write-Host $currentContext.Subscription.Name -ForegroundColor Cyan

    # CLEANUP MODE: Delete rulesets based on mapping file
    if ($CleanupMode) {
        Write-Host "`n" -NoNewline
        Write-Host "🧹 CLEANUP MODE ACTIVATED" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        
        # Get the new ruleset names from the mapping
        $rulesetsToDelete = $ruleSetMapping.Values | Sort-Object
        
        if ($rulesetsToDelete.Count -eq 0) {
            Write-Host "⚠️  " -NoNewline -ForegroundColor Yellow
            Write-Warning "No rulesets found in mapping file to delete"
            exit 0
        }
        
        Write-Host "The following rulesets will be DELETED from Front Door profile: " -NoNewline
        Write-Host $FrontDoorName -ForegroundColor Cyan
        Write-Host ""
        foreach ($rulesetName in $rulesetsToDelete) {
            Write-Host "  🗑️  " -NoNewline
            Write-Host $rulesetName -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "⚠️  WARNING: This action cannot be undone!" -ForegroundColor Yellow
        Write-Host ""
        
        # Prompt for confirmation
        $confirmation = Read-Host "Type 'DELETE' to confirm deletion, or anything else to cancel"
        
        if ($confirmation -ne 'DELETE') {
            Write-Host ""
            Write-Host "✅ Cleanup cancelled by user" -ForegroundColor Green
            Write-Host ""
            exit 0
        }
        
        Write-Host ""
        Write-Host "Starting deletion process..." -ForegroundColor Yellow
        Write-Host ""
        
        $successCount = 0
        $failCount = 0
        $notFoundCount = 0
        
        foreach ($rulesetName in $rulesetsToDelete) {
            Write-Host "Processing: " -NoNewline
            Write-Host $rulesetName -ForegroundColor Cyan
            
            try {
                # Check if ruleset exists
                $existingRuleset = Get-AzFrontDoorCdnRuleSet -ProfileName $FrontDoorName -ResourceGroupName $ResourceGroupName -RuleSetName $rulesetName -ErrorAction SilentlyContinue
                
                if (-not $existingRuleset) {
                    Write-Host "  ⚠️  Ruleset not found (already deleted or never existed)" -ForegroundColor Yellow
                    $notFoundCount++
                    continue
                }
                
                # Delete the ruleset
                Write-Host "  🗑️  Deleting ruleset..." -NoNewline
                Remove-AzFrontDoorCdnRuleSet -ProfileName $FrontDoorName -ResourceGroupName $ResourceGroupName -RuleSetName $rulesetName -ErrorAction Stop
                Write-Host " ✅ Deleted successfully" -ForegroundColor Green
                $successCount++
            }
            catch {
                Write-Host " ❌ Failed" -ForegroundColor Red
                Write-Host "     Error: $($_.Exception.Message)" -ForegroundColor Red
                $failCount++
            }
            Write-Host ""
        }
        
        # Summary
        Write-Host "CLEANUP SUMMARY"
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host "  Total rulesets in mapping : " -NoNewline
        Write-Host $rulesetsToDelete.Count -ForegroundColor Cyan
        Write-Host "  Successfully deleted       : " -NoNewline
        Write-Host $successCount -ForegroundColor Green
        Write-Host "  Not found                  : " -NoNewline
        Write-Host $notFoundCount -ForegroundColor Yellow
        Write-Host "  Failed                     : " -NoNewline
        Write-Host $failCount -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        
        if ($failCount -gt 0) {
            Write-Host ""
            Write-Host "⚠️  Some rulesets failed to delete. Check error messages above." -ForegroundColor Yellow
            exit 1
        }
        else {
            Write-Host ""
            Write-Host "✅ Cleanup completed successfully!" -ForegroundColor Green
            Write-Host ""
        }
        
        exit 0
    }

    # Get the Front Door profile (Get-AzFrontDoorCdnProfile only retrieves Standard/Premium profiles)
    Write-Host "Retrieving Front Door profile: " -NoNewline
    Write-Host "$FrontDoorName" -ForegroundColor Cyan -NoNewline
    Write-Host " in resource group: " -NoNewline
    Write-Host $ResourceGroupName -ForegroundColor Cyan
    $afdProfile = Get-AzFrontDoorCdnProfile -Name $FrontDoorName -ResourceGroupName $ResourceGroupName -ErrorAction Stop

    if (-not $afdProfile) {
        Write-Host "❌ " -NoNewline -ForegroundColor Red
        Write-Error "Front Door profile '$FrontDoorName' not found in resource group '$ResourceGroupName'"
        exit 1
    }

    $sku = $afdProfile.SkuName
    Write-Host "✅ Found Front Door profile with SKU: " -NoNewline -ForegroundColor Green
    Write-Host $sku -ForegroundColor Cyan

    # Get all rule sets
    Write-Host "Retrieving rule sets for profile: " -NoNewline
    Write-Host $FrontDoorName -ForegroundColor Cyan -NoNewline
    Write-Host "..."
    $ruleSets = Get-AzFrontDoorCdnRuleSet -ProfileName $FrontDoorName -ResourceGroupName $ResourceGroupName -ErrorAction Stop

    # Apply exclusion filters if specified
    if ($ExcludeRuleSets -and $ExcludeRuleSets.Count -gt 0) {
        $originalCount = if ($ruleSets -is [array]) { $ruleSets.Count } else { if ($ruleSets) { 1 } else { 0 } }
        $filteredRuleSets = @()
        foreach ($ruleSet in $ruleSets) {
            $exclude = $false
            foreach ($pattern in $ExcludeRuleSets) {
                if ($ruleSet.Name -like $pattern) {
                    $exclude = $true
                    Write-Host "  🚫 Excluding rule set: " -NoNewline
                    Write-Host $ruleSet.Name -ForegroundColor DarkGray
                    break
                }
            }
            if (-not $exclude) {
                $filteredRuleSets += $ruleSet
            }
        }
        $ruleSets = $filteredRuleSets
        $excludedCount = $originalCount - $filteredRuleSets.Count
        if ($excludedCount -gt 0) {
            Write-Host "✅ Excluded " -NoNewline -ForegroundColor Green
            Write-Host $excludedCount -ForegroundColor Cyan -NoNewline
            Write-Host " rule set(s)"
        }
    }

    if (-not $ruleSets) {
        Write-Host "⚠️  " -NoNewline -ForegroundColor Yellow
        Write-Warning "No rule sets found in Front Door profile '$FrontDoorName'"
        $ruleSetCount = 0
    }
    elseif ($ruleSets -is [array]) {
        $ruleSetCount = $ruleSets.Count
    }
    else {
        $ruleSetCount = 1
    }

    Write-Host "✅ Found " -NoNewline -ForegroundColor Green
    Write-Host $ruleSetCount -ForegroundColor Cyan -NoNewline
    Write-Host " rule set(s)"

    # If mapping file is provided, filter to only include rulesets in the mapping
    # This ensures the ARM template only contains the rulesets we want to duplicate
    # Unmapped rulesets are skipped - they won't be affected by the deployment (incremental mode)
    if ($RuleSetMappingFile -and $ruleSetMapping.Count -gt 0) {
        $originalCount = $ruleSetCount
        $mappedRuleSets = @()
        foreach ($ruleSet in $ruleSets) {
            if ($ruleSetMapping.ContainsKey($ruleSet.Name)) {
                $mappedRuleSets += $ruleSet
            }
            else {
                Write-Host "  ⏭️  Skipping unmapped rule set: " -NoNewline
                Write-Host $ruleSet.Name -ForegroundColor DarkGray
            }
        }
        $ruleSets = $mappedRuleSets
        $ruleSetCount = $mappedRuleSets.Count
        
        if ($originalCount -ne $ruleSetCount) {
            Write-Host "✅ Filtered to " -NoNewline -ForegroundColor Green
            Write-Host $ruleSetCount -ForegroundColor Cyan -NoNewline
            Write-Host " mapped rule set(s) (excluded " -NoNewline
            Write-Host ($originalCount - $ruleSetCount) -ForegroundColor DarkGray -NoNewline
            Write-Host " unmapped)"
        }
    }

    # Get detailed information for each rule set including rules
    $detailedRuleSets = @()
    
    if ($ruleSetCount -gt 0) {
        foreach ($ruleSet in $ruleSets) {
            Write-Host "  📦 Processing rule set: " -NoNewline
            Write-Host $ruleSet.Name -ForegroundColor Cyan
            
            # Get all rules for this rule set
            $rules = Get-AzFrontDoorCdnRule -ProfileName $FrontDoorName -ResourceGroupName $ResourceGroupName -RuleSetName $ruleSet.Name -ErrorAction Stop
            
            $ruleCount = if ($rules -is [array]) { $rules.Count } else { if ($rules) { 1 } else { 0 } }
            Write-Host "     ↳ Found " -NoNewline
            Write-Host $ruleCount -ForegroundColor Cyan -NoNewline
            Write-Host " rule(s)"
            
            # Create a custom object with rule set and its rules
            $detailedRuleSet = [PSCustomObject]@{
                RuleSet = $ruleSet
                Rules   = $rules
            }
            
            $detailedRuleSets += $detailedRuleSet
        }
    }

    # Create the deployment structure
    Write-Host "`nPreparing deployment JSON structure..."
    
    $deploymentObject = [PSCustomObject]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        metadata       = [PSCustomObject]@{
            description = "Azure Front Door rule sets export from profile: $FrontDoorName"
            exportDate  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
            sourceSku   = $sku
            comments    = 'Generated by update-afdjsonrulesets.ps1 - ARM template for ruleset deployment'
        }
        parameters     = [PSCustomObject]@{
            profileName = [PSCustomObject]@{
                type         = 'string'
                defaultValue = $FrontDoorName
                metadata     = [PSCustomObject]@{
                    description = 'Name of the Azure Front Door profile to deploy the rule sets to'
                }
            }
        }
        variables      = [PSCustomObject]@{}
        resources      = @()
    }

    # Add rule sets and their rules as resources
    if ($ruleSetCount -gt 0) {
        foreach ($detailedRuleSet in $detailedRuleSets) {
            $ruleSet = $detailedRuleSet.RuleSet
            $rules = $detailedRuleSet.Rules
            
            # Determine the final ruleset name (original or mapped)
            $originalRuleSetName = $ruleSet.Name
            $finalRuleSetName = if ($ruleSetMapping.ContainsKey($originalRuleSetName)) {
                $ruleSetMapping[$originalRuleSetName]
            } else {
                $originalRuleSetName
            }
            
            # Add rule set resource
            $ruleSetResource = [PSCustomObject]@{
                type       = 'Microsoft.Cdn/profiles/ruleSets'
                apiVersion = '2023-05-01'
                name       = "[concat(parameters('profileName'), '/', '$finalRuleSetName')]"
                properties = [PSCustomObject]@{}
            }
            
            $deploymentObject.resources += $ruleSetResource
            
            # Add each rule as a nested resource
            if ($rules) {
                $ruleArray = if ($rules -is [array]) { $rules } else { @($rules) }
                
                foreach ($rule in $ruleArray) {
                    # Convert conditions to ARM format
                    $armConditions = @()
                    if ($rule.Condition) {
                        foreach ($condition in $rule.Condition) {
                            $conditionParams = @{
                                typeName = $condition.ParameterTypeName
                            }
                            
                            # Add all Parameter* properties to parameters object (excluding ParameterTypeName)
                            $condition.PSObject.Properties | Where-Object { $_.Name -like 'Parameter*' -and $_.Name -ne 'ParameterTypeName' } | ForEach-Object {
                                $paramName = $_.Name -replace '^Parameter', ''
                                # Convert to camelCase
                                $paramName = $paramName.Substring(0, 1).ToLower() + $paramName.Substring(1)
                                # Handle singular to plural conversions for ARM template
                                if ($paramName -eq 'matchValue') { $paramName = 'matchValues' }
                                if ($paramName -eq 'transform') { $paramName = 'transforms' }
                                $conditionParams[$paramName] = $_.Value
                            }
                            
                            $armConditions += [PSCustomObject]@{
                                name       = $condition.Name
                                parameters = [PSCustomObject]$conditionParams
                            }
                        }
                    }
                    
                    # Convert actions to ARM format
                    $armActions = @()
                    if ($rule.Action) {
                        foreach ($action in $rule.Action) {
                            $actionParams = @{
                                typeName = $action.ParameterTypeName
                            }
                            
                            # Add all Parameter* and other specific properties to parameters object
                            $action.PSObject.Properties | Where-Object { 
                                ($_.Name -like 'Parameter*' -and $_.Name -ne 'ParameterTypeName') -or
                                $_.Name -like 'CacheConfiguration*' -or
                                $_.Name -like 'OriginGroup*'
                            } | ForEach-Object {
                                $paramName = $_.Name -replace '^Parameter', '' -replace '^CacheConfiguration', '' -replace '^OriginGroup', ''
                                
                                # Handle nested objects for RouteConfigurationOverride and OriginGroupOverride
                                if ($action.Name -eq 'RouteConfigurationOverride') {
                                    if ($_.Name -like 'CacheConfiguration*') {
                                        if (-not $actionParams['cacheConfiguration']) {
                                            $actionParams['cacheConfiguration'] = @{}
                                        }
                                        $cacheParamName = $paramName.Substring(0, 1).ToLower() + $paramName.Substring(1)
                                        $actionParams['cacheConfiguration'][$cacheParamName] = $_.Value
                                    }
                                    elseif ($_.Name -like 'OriginGroup*') {
                                        if (-not $actionParams['originGroupOverride']) {
                                            $actionParams['originGroupOverride'] = @{}
                                        }
                                        if ($_.Name -eq 'OriginGroupId') {
                                            if (-not $actionParams['originGroupOverride']['originGroup']) {
                                                $actionParams['originGroupOverride']['originGroup'] = @{}
                                            }
                                            $actionParams['originGroupOverride']['originGroup']['id'] = $_.Value
                                        }
                                        elseif ($_.Name -eq 'OriginGroupOverrideForwardingProtocol') {
                                            $actionParams['originGroupOverride']['forwardingProtocol'] = $_.Value
                                        }
                                    }
                                }
                                elseif ($action.Name -eq 'OriginGroupOverride') {
                                    if ($_.Name -eq 'OriginGroupId') {
                                        if (-not $actionParams['originGroup']) {
                                            $actionParams['originGroup'] = @{}
                                        }
                                        $actionParams['originGroup']['id'] = $_.Value
                                    }
                                }
                                else {
                                    # Standard parameter conversion
                                    $paramName = $paramName.Substring(0, 1).ToLower() + $paramName.Substring(1)
                                    $actionParams[$paramName] = $_.Value
                                }
                            }
                            
                            # Remove cacheConfiguration if all its properties are null or empty
                            if ($actionParams.ContainsKey('cacheConfiguration')) {
                                $cacheConfig = $actionParams['cacheConfiguration']
                                $hasValue = $false
                                foreach ($key in $cacheConfig.Keys) {
                                    if ($null -ne $cacheConfig[$key] -and $cacheConfig[$key] -ne '') {
                                        $hasValue = $true
                                        break
                                    }
                                }
                                if (-not $hasValue) {
                                    $actionParams.Remove('cacheConfiguration')
                                }
                            }
                            
                            # Remove originGroupOverride if all its properties are null or empty
                            if ($actionParams.ContainsKey('originGroupOverride')) {
                                $ogOverride = $actionParams['originGroupOverride']
                                $hasValue = $false
                                # Check if originGroup.id has value
                                if ($ogOverride.ContainsKey('originGroup') -and $ogOverride['originGroup'].ContainsKey('id')) {
                                    if ($null -ne $ogOverride['originGroup']['id'] -and $ogOverride['originGroup']['id'] -ne '') {
                                        $hasValue = $true
                                    }
                                }
                                # Check if forwardingProtocol has value
                                if ($ogOverride.ContainsKey('forwardingProtocol')) {
                                    if ($null -ne $ogOverride['forwardingProtocol'] -and $ogOverride['forwardingProtocol'] -ne '') {
                                        $hasValue = $true
                                    }
                                }
                                if (-not $hasValue) {
                                    $actionParams.Remove('originGroupOverride')
                                }
                            }
                            
                            # Remove standalone originGroup if id is null or empty (for OriginGroupOverride action)
                            if ($actionParams.ContainsKey('originGroup')) {
                                $og = $actionParams['originGroup']
                                if ($og -is [hashtable] -and $og.ContainsKey('id')) {
                                    if ($null -eq $og['id'] -or $og['id'] -eq '') {
                                        $actionParams.Remove('originGroup')
                                    }
                                }
                            }
                            
                            # Remove queryStringParameters if empty or all values are null
                            if ($actionParams.ContainsKey('queryStringParameters')) {
                                $qsp = $actionParams['queryStringParameters']
                                if ($qsp -is [hashtable] -and $qsp.Count -eq 0) {
                                    $actionParams.Remove('queryStringParameters')
                                }
                                elseif ($qsp -is [hashtable]) {
                                    $hasValue = $false
                                    foreach ($key in $qsp.Keys) {
                                        if ($null -ne $qsp[$key] -and $qsp[$key] -ne '') {
                                            $hasValue = $true
                                            break
                                        }
                                    }
                                    if (-not $hasValue) {
                                        $actionParams.Remove('queryStringParameters')
                                    }
                                }
                            }
                            
                            # Remove empty arrays from parameters
                            $keysToRemove = @()
                            foreach ($key in $actionParams.Keys) {
                                $value = $actionParams[$key]
                                if ($value -is [array] -and $value.Count -eq 0) {
                                    $keysToRemove += $key
                                }
                            }
                            foreach ($key in $keysToRemove) {
                                $actionParams.Remove($key)
                            }
                            
                            $armActions += [PSCustomObject]@{
                                name       = $action.Name
                                parameters = [PSCustomObject]$actionParams
                            }
                        }
                    }
                    
                    $ruleResource = [PSCustomObject]@{
                        type       = 'Microsoft.Cdn/profiles/ruleSets/rules'
                        apiVersion = '2023-05-01'
                        name       = "[concat(parameters('profileName'), '/', '$finalRuleSetName', '/', '$($rule.Name)')]"
                        dependsOn  = @(
                            "[resourceId('Microsoft.Cdn/profiles/ruleSets', parameters('profileName'), '$finalRuleSetName')]"
                        )
                        properties = [PSCustomObject]@{
                            order                   = $rule.Order
                            conditions              = $armConditions
                            actions                 = $armActions
                            matchProcessingBehavior = $rule.MatchProcessingBehavior
                        }
                    }
                    
                    $deploymentObject.resources += $ruleResource
                }
            }
        }
    }

    Write-Host "✅ Deployment template created with " -NoNewline -ForegroundColor Green
    Write-Host $deploymentObject.resources.Count -ForegroundColor Cyan -NoNewline
    Write-Host " resource(s)"

    # Convert to JSON with appropriate depth
    $jsonOutput = $deploymentObject | ConvertTo-Json -Depth 100

    # Output or save the JSON
    if ($OutputPath) {
        Write-Host "`nSaving JSON to: " -NoNewline
        Write-Host $OutputPath -ForegroundColor Cyan
        $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host "✅ Successfully saved!" -ForegroundColor Green
    }
    else {
        Write-Host "`n" -NoNewline
        Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host "                         JSON OUTPUT                          " -ForegroundColor Cyan
        Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Output $jsonOutput
        Write-Host "═════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    }

    Write-Host "`n" -NoNewline
    Write-Host "SUMMARY"
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  Front Door Profile : " -NoNewline
    Write-Host $FrontDoorName -ForegroundColor Cyan
    Write-Host "  Resource Group     : " -NoNewline
    Write-Host $ResourceGroupName -ForegroundColor Cyan
    Write-Host "  SKU                : " -NoNewline
    Write-Host $sku -ForegroundColor Cyan
    Write-Host "  Rule Sets          : " -NoNewline
    Write-Host $ruleSetCount -ForegroundColor Cyan
    if ($ruleSetMapping.Count -gt 0) {
        Write-Host "  Renamed Rule Sets  : " -NoNewline
        Write-Host $ruleSetMapping.Count -ForegroundColor Cyan
    }
    Write-Host "  Total Resources    : " -NoNewline
    Write-Host $deploymentObject.resources.Count -ForegroundColor Cyan
    
    Write-Host "`n" -NoNewline
    Write-Host "NEXT STEPS"
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    if ($OutputPath) {
        Write-Host "  1. Review the exported JSON file: " -NoNewline
        Write-Host $OutputPath -ForegroundColor Cyan
    } else {
        Write-Host "  1. Save the JSON output to a file (copy from above or re-run with -OutputPath):"
        Write-Host "      .\update-afdjsonrulesets.ps1 -FrontDoorName '$FrontDoorName' -ResourceGroupName '$ResourceGroupName' -OutputPath '.\$FrontDoorName-rulesets.json'" -ForegroundColor Gray
    }
    if ($ruleSetMapping.Count -gt 0) {
        Write-Host "  2. " -NoNewline
        Write-Host "✅ Rulesets already renamed via mapping file" -ForegroundColor Green
    } else {
        Write-Host "  2. Rename the rule sets manually in JSON, or create a mapping file:"
        Write-Host "      Format: OldRuleSetName=NewRuleSetName (one per line)" -ForegroundColor Gray
        Write-Host "      Then re-run with -RuleSetMappingFile parameter" -ForegroundColor Gray
    }
    Write-Host "  3. Validate the template:"
    if ($OutputPath) {
        Write-Host "      Test-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '$OutputPath' -Verbose" -ForegroundColor Gray
    } else {
        Write-Host "      Test-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '<path-to-json>' -Verbose" -ForegroundColor Gray
    }
    Write-Host "  4. Preview what will be created/modified:"
    if ($OutputPath) {
        Write-Host "      New-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '$OutputPath' -WhatIf -Verbose" -ForegroundColor Gray
    } else {
        Write-Host "      New-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '<path-to-json>' -WhatIf -Verbose" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "      ⚠️  IMPORTANT: Verify your RENAMED rulesets show as 'create' (+)" -ForegroundColor Yellow
    Write-Host "          Un-renamed rulesets will show as 'no change' (=)"
    Write-Host ""
    Write-Host "  5. Deploy the template:"
    if ($OutputPath) {
        Write-Host "      New-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '$OutputPath' -Verbose" -ForegroundColor Gray
    } else {
        Write-Host "      New-AzResourceGroupDeployment -ResourceGroupName '$ResourceGroupName' -TemplateFile '<path-to-json>' -Verbose" -ForegroundColor Gray
    }
    Write-Host "  6. Or deploy via Azure Portal using Custom Deployment"
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

}
catch {
    Write-Host "`n❌ " -NoNewline -ForegroundColor Red
    Write-Host "ERROR OCCURRED" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Error "An error occurred: $_"
    Write-Error $_.Exception.Message
    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
    }
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    exit 1
}
