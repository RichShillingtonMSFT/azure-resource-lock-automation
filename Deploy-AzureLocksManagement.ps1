<#
.SYNOPSIS
    Script to deploy Resource Lock Management using Azure Automation

.DESCRIPTION
    This script will deploy Resource Lock Management using Azure Automation.
    It will create an Automation account, a runas account.
    It will create a Key Vault if the one specified does not exist.
    It will create a custom RBAC role to allow for management of resource locks on the entire subscription
    as well as creates and publishes all the nessecary runbooks and variables.

.PARAMETER AutomationAccountName
    Name for the new Automation Account.
    Example: "Locks-Automation-Acct"

.PARAMETER AutomationAccountResourceGroupName
    Name of the Resource Group where this will be deployed.
    Example: "Locks-Automation-RG"

.PARAMETER KeyVaultName
    Name of the Key Vault where the Certificate will be created.
    Example: "Secrets-KV"

.PARAMETER ScopeSubscriptionID
    Enter Subscription ID where the custom RBAC should be scoped. 
    Example: '7cd89fb7-c577-4bb8-ac33-790b9580da6f'

.PARAMETER RBACStoreSubscriptionID
    Enter the Subscription ID where Custom RBAC Roles should be stored
    Example: 'dee1e1fb-a70e-47bd-95cd-4394e718b1d7'

.EXAMPLE
    .\Deploy-AzureLocksManagement.ps1 -AutomationAccountName 'Locks-Automation-Acct' `
        -AutomationAccountResourceGroupName 'Locks-Automation-RG' `
        -KeyVaultName 'Automation-KV' `
        -ScopeSubscriptionID '7cd89fb7-c577-4bb8-ac33-790b9580da6f' `
        -RBACStoreSubscriptionID '7cd89fb7-c577-4bb8-ac33-790b9580da6f'
#>
[CmdletBinding()]
Param
(
    # Name for the new Automation Account.
    # Example: "Locks-Automation-Acct"
    [parameter(Mandatory=$true,HelpMessage='Name for the new Automation Account. Example: Locks-Automation-Acct')]
    [String]$AutomationAccountName,

    # Name of the Resource Group where this will be deployed.
    # Example: "Locks-Automation-RG"
    [parameter(Mandatory=$true,HelpMessage='Name of the Resource Group where this will be deployed. Example: Locks-Automation-RG')]
    [String]$AutomationAccountResourceGroupName,

    # Name of the Key Vault where the Certificate will be created.
    # Example: "Secrets-KV"
    [parameter(Mandatory=$true,HelpMessage='Name of the Key Vault where the Certificate will be created. Example: Secrets-KV')]
    [String]$KeyVaultName,

    # Enter Subscription ID where the custom RBAC should be scoped. 
    # Example: '7cd89fb7-c577-4bb8-ac33-790b9580da6f'
    [parameter(Mandatory=$false,HelpMessage='Example: 7cd89fb7-c577-4bb8-ac33-790b9580da6f')]
    [String]$ScopeSubscriptionID,

    # Enter the Subscription ID where Custom RBAC Roles should be stored
    # Example: 'dee1e1fb-a70e-47bd-95cd-4394e718b1d7'
    [parameter(Mandatory=$false,HelpMessage='Example: dee1e1fb-a70e-47bd-95cd-4394e718b1d7')]
    [String]$RBACStoreSubscriptionID
)

#Requires -Modules @{ModuleName="Az.Storage"; ModuleVersion="1.14.0"}
#Requires -Modules @{ModuleName="Az.Accounts"; ModuleVersion="1.7.5"}
#Requires -Modules @{ModuleName="Az.Automation"; ModuleVersion="1.3.6"}

# Set verbose preference
$VerbosePreference = 'Continue'

#region Enviornment Selection
$Environment = Get-AzEnvironment | Out-GridView -Title "Please Select an Azure Enviornment." -PassThru
#endregion

#region Connect to Azure
try
{
    Connect-AzAccount -Environment $($Environment.Name) -ErrorAction 'Stop'
}
catch
{
    Write-Error -Message $_.Exception
    break
}
#endregion

#region Subscription Selection
try 
{
    $Subscriptions = Get-AzSubscription
    if ($Subscriptions.Count -gt '1')
    {
        $Subscription = $Subscriptions | Out-GridView -Title "Please Select a Subscription." -PassThru
        Set-AzContext $Subscription
    }
}
catch
{
    Write-Error -Message $_.Exception
    break
}
#endregion

#region Location Selection
$Location = (Get-AzLocation | Out-GridView -Title "Please Select a location." -PassThru).Location
#endregion

#region Resource Group
# Create the resource group if needed
try 
{
    Get-AzResourceGroup -Name $AutomationAccountResourceGroupName -ErrorAction 'Stop'
    Write-Output "Found Resource Group $AutomationAccountResourceGroupName"
}
catch 
{
    Write-Output "Creating Resource Group $AutomationAccountResourceGroupName"
    New-AzResourceGroup -Name $AutomationAccountResourceGroupName -Location $Location -ErrorAction 'Stop'
}
#endregion

#region Deploy Automation Account
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "2.0.0.0",
    "parameters": {
        "automationAccountName": {
            "type": "string"
        },
        "automationAccountLocation": {
            "type": "string"
        },
        "automationAccountResourceGroupName": {
            "type": "string"
        }
    },
    "resources": [
        {
            "type": "Microsoft.Automation/automationAccounts",
            "apiVersion": "[providers('Microsoft.Automation','automationAccounts').apiVersions[0]]",
            "name": "[parameters('automationAccountName')]",
            "location": "[parameters('automationAccountLocation')]",
            "dependsOn": [],
            "properties": {
                "sku": {
                    "name": "Basic"
                }
            }
        }
    ],
    "outputs": {
        "automationAccountName": {
          "type": "string",
          "value": "[parameters('automationAccountName')]"
        },
        "automationAccountResourceGroupName":{
            "type": "string",
            "value": "[parameters('automationAccountResourceGroupName')]"
        },
        "automationAccountLocation":{
            "type": "string",
            "value": "[parameters('automationAccountLocation')]"
        }
    }
}
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        },
        "automationAccountResourceGroupName": {
            "value": "$AutomationAccountResourceGroupName"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Azure Automation Account. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Azure Automation Account Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Deploy Keyvault if not found
$KeyVault = Get-AzKeyVault -VaultName $KeyVaultName

if (!$KeyVault)
{
    New-AzKeyVault -Name $KeyVaultName -ResourceGroupName $AutomationAccountResourceGroupName -Sku Standard -Location $Location
    $KeyVault = Get-AzKeyVault -VaultName $KeyVaultName
}
#endregion

#region Create Custom RBAC Role
$AzureContext = Get-AzContext
$SubscriptionID = $($AzureContext.Subscription.Id)
$TenantID = $($AzureContext.Subscription.TenantId)

if (!$ScopeSubscriptionID)
{
    $ScopeSubscriptionID = $SubscriptionID
}
if (!$RBACStoreSubscriptionID)
{
    $RBACStoreSubscriptionID = $SubscriptionID
}

Write-Output "Looking for Azure Lock Managemement Role"
$RequiredBaselinePermissions = @(
'Microsoft.Authorization/locks/*'
)

$CustomRole = Get-AzRoleDefinition -Name 'Azure Lock Managemement'
if (!$CustomRole)
{
    Write-Output "Creating Azure Lock Managemement Custom Role"

    $NewRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
    $NewRole.Name = 'Azure Lock Managemement'
    $NewRole.Description = 'Can manage all Azure Resource Locks'
    $NewRole.IsCustom = $true
    $NewRole.Actions = $RequiredBaselinePermissions
    $NewRole.AssignableScopes = "/subscriptions/$RBACStoreSubscriptionID"
    New-AzRoleDefinition -Role $NewRole -Verbose -ErrorAction 'Stop'
    $CustomRole = Get-AzRoleDefinition -Name 'Azure Lock Managemement'
}

if ($CustomRole)
{
    Write-Output "Azure Lock Managemement Role found. Checking Permissions and Scopes."
    foreach ($RequiredBaselinePermission in $RequiredBaselinePermissions)
    {
        if ($RequiredBaselinePermission -notin $CustomRole.Actions)
        {
            $CustomRole.Actions.Add($RequiredBaselinePermission) 
        }
    }
    if ("/subscriptions/$ScopeSubscriptionID" -notin $CustomRole.AssignableScopes)
    {
        $CustomRole.AssignableScopes.Add("/subscriptions/$ScopeSubscriptionID")
    }
    
    $CustomRole | Set-AzRoleDefinition
}
#endregion

#region Automation Account Certificate
[String] $ApplicationDisplayName = $AutomationAccountName
[String] $SelfSignedCertPlainPassword = [Guid]::NewGuid().ToString().Substring(0, 8) + "!" 
[int]$NumberOfMonthsUntilExpired = '36'
$CertifcateAssetName = "AzureRunAsCertificate"
$CertificateName = $AutomationAccountName + $CertifcateAssetName
$PfxCertificatePathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
$PfxCertificatePlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
$CerCertificatePathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")
$CertificateSubjectName = "cn=" + $CertificateName

# Create Certificate Using Key Vault
Write-Output "Generating the Automation Account Certificate using Key Vault $KeyVaultName"

Write-Output 'Creating Key Vault Certificate Policy'
$Policy = New-AzureKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $CertificateSubjectName -IssuerName "Self" -ValidityInMonths $NumberOfMonthsUntilExpired -ReuseKeyOnRenewal

try 
{
    Write-Output 'Adding Azure Key Vault Certificate'
    $AddAzureKeyVaultCertificateStatus = Add-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $Policy -ErrorAction 'Stop'
    While ($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress")
    {
        Start-Sleep -s 10
        $AddAzureKeyVaultCertificateStatus = Get-AzureKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $CertificateName
    }
}
catch 
{
    Write-Error -Message "Key vault certificate creation was not successful."
    break
}
#endregion

#region Create RunAsAccount
# Get Certificate Information from Key Vault
Write-Output "Get Certificate Information from Key Vault $KeyVaultName"
$SecretRetrieved = Get-AzureKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -ErrorAction 'Stop'
$PfxBytes = [System.Convert]::FromBase64String($SecretRetrieved.SecretValueText)
$CertificateCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$CertificateCollection.Import($PfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
   
# Export  the .pfx file 
$protectedCertificateBytes = $CertificateCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertificatePlainPasswordForRunAsAccount)
[System.IO.File]::WriteAllBytes($PfxCertificatePathForRunAsAccount, $protectedCertificateBytes)

# Export the .cer file 
$Certificate = Get-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -ErrorAction 'Stop'
$CertificateBytes = $Certificate.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($CerCertificatePathForRunAsAccount, $CertificateBytes)

Write-Output "Creating Service Principal"
# Create Service Principal
$PfxCertificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertificatePathForRunAsAccount, $PfxCertificatePlainPasswordForRunAsAccount)
$KeyValue = [System.Convert]::ToBase64String($PfxCertificate.GetRawCertData())
$KeyId = [Guid]::NewGuid()
$StartDate = Get-Date
$EndDate = (Get-Date $PfxCertificate.GetExpirationDateString()).AddDays(-1)

# Use Key credentials and create AAD Application
Write-Output "Creating Azure AD Application"
try
{
    $Application = New-AzADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $KeyId) -ErrorAction 'Stop'
    New-AzADAppCredential -ApplicationId $Application.ApplicationId -CertValue $KeyValue -StartDate $StartDate -EndDate $EndDate -ErrorAction 'Stop'
    New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
    break
}

# Allow the service principal application to become active
Start-Sleep -s 30
Write-Output "Service Principal created successfully"

# Create the automation certificate asset
Write-Output "Creating Automation Certificate"
$CertificatePassword = ConvertTo-SecureString $PfxCertificatePlainPasswordForRunAsAccount -AsPlainText -Force
try
{
    New-AzAutomationCertificate -ResourceGroupName $AutomationAccountResourceGroupName -automationAccountName $AutomationAccountName -Path $PfxCertificatePathForRunAsAccount -Name $CertifcateAssetName -Password $CertificatePassword -Exportable -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}

# Populate the Connection Field Values
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionFieldValues = @{"ApplicationId" = $($Application.ApplicationId); "TenantId" = $TenantID; "CertificateThumbprint" = $($PfxCertificate.Thumbprint); "SubscriptionId" = $SubscriptionID} 

# Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
Write-Output "Creating Automation Connection"
try
{
    New-AzAutomationConnection -ResourceGroupName $AutomationAccountResourceGroupName -automationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
Write-Output "Automation Account $AutomationAccountName creation & configuration completed successfully"
#endregion

#region Assign Automation Account Permissions
# Assign Contributor to Automation Account
Write-Output "Assigning Contributor of the Automation Account to the Automation Account Resource Group"
New-AzRoleAssignment -RoleDefinitionName 'Contributor' -ApplicationId $Application.ApplicationId -Scope "/subscriptions/$ScopeSubscriptionID/resourceGroups/$AutomationAccountResourceGroupName" -ErrorVariable ErrorCheck -ErrorAction Stop
$ErrorCheck | ForEach-Object {
    if ($_ -notlike "*already exists*")
    {
        throw "Error assigning Contributor to the Automation Account."
        break
    }
}

# Assign Azure Lock Managemement to Automation Account
Write-Output "Assigning Azure Lock Managemement to the Automation Account"
New-AzRoleAssignment -RoleDefinitionName 'Azure Lock Managemement' -ApplicationId $Application.ApplicationId -Scope "/subscriptions/$ScopeSubscriptionID" -ErrorVariable ErrorCheck -ErrorAction Stop
$ErrorCheck | ForEach-Object {
    if ($_ -notlike "*already exists*")
    {
        throw "Error assigning Azure Lock Managemement to the Automation Account."
        break
    }
}

# Assign Key Vault Contributor
Write-Output "Assigning Key Vault Contributor to the Automation Account"
New-AzRoleAssignment -RoleDefinitionName 'Contributor' -ApplicationId $Application.ApplicationId -Scope ($KeyVault.ResourceId) -ErrorVariable ErrorCheck -ErrorAction Stop
$ErrorCheck | ForEach-Object {
    if ($_ -notlike "*already exists*")
    {
        throw "Error assigning Azure Lock Managemement to the Automation Account."
        break
    }
}
#endregion

#region Create Daily Schedule
$DailyScheduleName = 'Every Day Once a Day'
Write-Output "Creating Automation Schedule Name $DailyScheduleName"
try
{
    New-AzAutomationSchedule -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Name $DailyScheduleName -StartTime (Get-Date "21:00:00") -DayInterval 1 -Verbose -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
}
Write-Output "Creation of Azure Automation Schedules completed successfully"
#endregion

#region Create, Import, Publish and Schedule Runbooks
Write-Output "Creating, Importing, Publishing and Scheduling Runbooks. This may take some time.."

#region Add Import-AzureLocksToTableStorage.ps1 Runbook and set a daily run schedule
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Import-AzureLocksToTableStorage.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to find all locks in the subscription and add them to a database.

.DESCRIPTION
    This Runbook is used to find all locks in the subscription and add them to a database.
    Every lock that is found is added as a individual entry.
    All Lock information is stored including Name, Description, Lock Level and target resource.
    The default schedule is to run this once per day.

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Import-AzureLocksToTableStorage.ps1

#>
[CmdletBinding()]
param
(                
    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $StorageAccountReportsContainerName = Get-AutomationVariable -Name 'ReportsContainer'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

#region Create Hash Function to Generate Row Keys for Data
function Get-TextHash
{
    param
    ( 
        [int] $Length = 30,
        [string] $Text
    )
    $Hasher = new-object System.Security.Cryptography.SHA256Managed
    $ToHash = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $HashByteArray = $Hasher.ComputeHash($ToHash)
    foreach($Byte in $HashByteArray)
    {
         $Result += $Byte.ToString()
    }

    return $Result.substring($Result.length - $Length, $Length)
}
#endregion

# Get Azure Locks and Locks Table Data
$ResourceLocks = Get-AzResourceLock -ErrorAction Stop -Verbose
$LocksInTableStorage = Get-AzTableRow -table $cloudTable -partitionKey $LocksKey -ErrorAction Stop -Verbose

#region Update Table with New Locks
foreach ($ResourceLock in $ResourceLocks | Where-Object {$_.LockId -notin $LocksInTableStorage.LockId})
{
    $LockProperties = @{}
    $ResourceLock.PSObject.Properties | Where-Object {$_.Name -ne 'Properties'} | ForEach-Object {
        if (!$_.Value) {$_.Value = ''}
        $LockProperties += @{$($_.Name)=$($_.Value)}
    }      
    $ResourceLock.Properties | Get-Member -type NoteProperty | foreach-object {
        $Name = $_.Name; 
        $Value = $ResourceLock.Properties."$($_.Name)"
        if (!$Value) {$Value = ''}
        $LockProperties += @{$Name=$value}
    }

    $LockProperties += @{TimeRemoved='null';TimeToRestore='null';IsRemoved='False';IsDeleted='False';DeletedOn='null'}

    $RowKey = (Get-TextHash -Text $($ResourceLock.ResourceId))

    Add-AzTableRow -table $CloudTable -partitionKey $LocksKey -rowKey ("$RowKey") -property $LockProperties -ErrorAction Stop
}
#endregion

#region Update Table with Missing Locks
foreach ($LockInTableStorage in $LocksInTableStorage | Where-Object {($_.LockId -notin $ResourceLocks.LockId) -and ($_.IsRemoved -ne 'True') -and ($_.IsDeleted -ne 'True')})
{
    try
    {
        Write-Host "Lock $($LockInTableStorage.Name) has been removed outside of automation."
        Write-Host "Changing state to IsDeleted"
        $LockInTableStorage.IsDeleted = 'True'
        $LockInTableStorage.DeletedOn = 'Unknown'
        $LockInTableStorage | Update-AzTableRow -table $cloudTable
    }
    catch
    {
        Write-Error "Failed to update lock table"
        $_
    }

}
#endregion

#region Remove Reports Older than 1 day
$DeleteBlobsDate = (Get-Date).AddDays(-1)
$Blobs = Get-AzStorageBlob -Context $StorageAccount.Context -Container $StorageAccountReportsContainerName

foreach($Blob in $Blobs)
{
    $BlobDate = [datetime]$Blob.LastModified.UtcDateTime
    if($BlobDate -le $DeleteBlobsDate) 
    {
        Remove-AzStorageBlob -Container $StorageAccountReportsContainerName -Blob $Blob.Name -Context $StorageAccount.Context -Force
    }

}
#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
    Register-AzAutomationScheduledRunbook -RunbookName $($RunbookFilePath.BaseName) -ScheduleName $DailyScheduleName -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Delete-AzureLock.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Delete-AzureLock.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to permanently delete a Resource Lock

.DESCRIPTION
    This Runbook is used to permanently delete a Resource Lock. 
    The Runbook will remove the Resource Lock from Azure as well as remove the corresponding database entry for the lock.

.PARAMETER LockedResourceID
    Provide Resource ID which contains the lock
    Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'

.PARAMETER LockName
    Provide the Name of the lock to remove
    Example: "Key Vault No Delete Lock"

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Delete-AzureLock.ps1 `
        -LockedResourceID '/subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault' `
        -LockName 'Key Vault No Delete Lock'

#>
[CmdletBinding()]
param
(
    # Provide Resource ID which contains the lock
    # Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'
    [parameter(Mandatory=$true,HelpMessage='Provide Resource ID which contains the lock. Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault')]
    [String]$LockedResourceID,

    # Provide the Name of the lock to remove
    # Example: "Key Vault No Delete Lock"
    [parameter(Mandatory=$true,HelpMessage='Provide the Name of the lock to remove. Example: Key Vault No Delete Lock')]
    [String]$LockName,

    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

# Build Custom Locks Table Filter
$LockID = $LockedResourceID + '/providers/Microsoft.Authorization/locks/' + $LockName
[string]$filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("LockId",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$LockID)

# Get Azure Locks and Locks Table Data
$ResourceLock = Get-AzTableRow -table $cloudTable -customFilter $filter
$AzureResourceLock = Get-AzResourceLock | Where-Object {$_.LockId -eq $($ResourceLock.LockId)}

#region Remove Lock and Update Tables
try
{
    $AzureResourceLock | Remove-AzResourceLock -Force -ErrorAction Stop
    $ResourceLock.IsDeleted = 'True'
    $ResourceLock.DeletedOn = (Get-Date -Format s)
    $ResourceLock | Update-AzTableRow -table $cloudTable
}
catch
{
    Write-Error "Failed to Remove Resource Lock"
    $_
}
#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Create-AzureLock.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Create-AzureLock.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to create new Azure Resource Locks.

.DESCRIPTION
    This Runbook is used to create new Azure Resource Locks.
    The Runbook will create the on the specified Azure Resource as well as add a corresponding database entry for the lock.

.PARAMETER LockedResourceID
    Provide Resource ID where the lock should be applied
    Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'

.PARAMETER LockName
    Provide a Name for the new lock
    Example: "Key Vault No Delete Lock"

.PARAMETER LockDescription
    Provide a description for the new lock
    Example: "Lock to Protect Production Key Vault from Deletion"

.PARAMETER LockLevel
    Provide the lock level setting.
    Example: ReadOnly or CanNotDelete

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Create-AzureLock.ps1 `
        -LockedResourceID '/subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault' `
        -LockName 'Key Vault No Delete Lock' `
        -LockDescription 'Lock to Protect Production Key Vault from Deletion'
        -LockLevel 'CanNotDelete'
#>
[CmdletBinding()]
param
(
    # Provide Resource ID where the lock should be applied
    # Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'
    [parameter(Mandatory=$true,HelpMessage='Provide Resource ID where the lock should be applied. Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault')]
    [String]$LockedResourceID,

    # Provide a Name for the new lock
    # Example: "KeyVault01 No Delete Lock"
    [parameter(Mandatory=$true,HelpMessage='Provide a Name for the new lock. Example: KeyVault01 No Delete Lock')]
    [String]$LockName,

    # Provide a description for the new lock
    # Example: "Lock to Protect Production Key Vault from Deletion"
    [parameter(Mandatory=$true,HelpMessage='Provide a description for the new lock. Example: Lock to Protect Production Key Vault from Deletion')]
    [String]$LockDescription,

    # Provide the lock level setting.
    # Example: ReadOnly or CanNotDelete
    [parameter(Mandatory=$true,HelpMessage='Provide the lock level setting. Example: ReadOnly or CanNotDelete')]
    [ValidateSet('CanNotDelete','ReadOnly')]
    [String]$LockLevel,

    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Remove Invalid Charachters from Lock Name
$InvalidCharachters = ([IO.Path]::GetInvalidFileNameChars() -join '') + '.!@#$%^&;'
$InvalidCharachtersRegex = "[{0}]" -f [RegEx]::Escape($InvalidCharachters)
$LockName = $LockName -replace "$InvalidCharachtersRegex", ""

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

#region Create Hash Function to Generate Row Keys for Data
function Get-TextHash
{
    param
    ( 
        [int] $Length = 30,
        [string] $Text
    )
    $Hasher = new-object System.Security.Cryptography.SHA256Managed
    $ToHash = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $HashByteArray = $Hasher.ComputeHash($ToHash)
    foreach($Byte in $HashByteArray)
    {
         $Result += $Byte.ToString()
    }

    return $Result.substring($Result.length - $Length, $Length)
}
#endregion

# Build Custom Locks Table Filter
$LockID = $LockedResourceID + '/providers/Microsoft.Authorization/locks/' + $LockName
[string]$filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("LockId",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$LockID)

# Get Azure Locks and Locks Table Data
$ResourceLock = Get-AzResourceLock | Where-Object {$_.LockId -eq $LockID}
$LocksInTableStorage = Get-AzTableRow -table $cloudTable -partitionKey $LocksKey

# Get Azure Locks and Locks Table Data
$ResourceLock = Get-AzTableRow -table $cloudTable -customFilter $filter
$AzureResourceLock = Get-AzResourceLock | Where-Object {$_.LockId -eq $($ResourceLock.LockId)}

if (($AzureResourceLock) -or ($ResourceLock))
{
    Write-Output "Lock $LockName already exists for resource $LockedResourceID"
    break
}
else
{
    Write-Output "Lock $LockName does not exist for resource $LockedResourceID"
    Write-Output "Creating Lock"
}

try
{
    $ResourceLock = New-AzResourceLock -LockLevel $LockLevel -LockName $LockName -Scope $LockedResourceID -LockNotes $LockDescription -Force -ErrorAction Stop
    Write-Output "Resource Lock Created Successfully"
}
catch
{
    Write-Error "Failed to create resource lock!"
    Write-Error $_
    $_ | FL -force
    break
}

#region Update Table with New Locks
try
{
    Write-Output "Updating Lock Table with new lock information"
    $LockProperties = @{}

    $ResourceLock.PSObject.Properties | Where-Object {$_.Name -ne 'Properties'} | ForEach-Object {
        if (!$_.Value) {$_.Value = ''}
        $LockProperties += @{$($_.Name)=$($_.Value)}
}      
    $ResourceLock.Properties | Get-Member -type NoteProperty | foreach-object {
        $Name = $_.Name; 
        $Value = $ResourceLock.Properties."$($_.Name)"
        if (!$Value) {$Value = ''}
        $LockProperties += @{$Name=$value}
}

    $LockProperties += @{TimeRemoved='null';TimeToRestore='null';IsRemoved='False';IsDeleted='False';DeletedOn='null'}

    $RowKey = (Get-TextHash -Text $($ResourceLock.ResourceId))

    Add-AzTableRow -table $CloudTable -partitionKey $LocksKey -rowKey ("$RowKey") -property $LockProperties -ErrorAction Stop
}
catch
{
    Write-Error "Failed to update lock table. Will try again during the import cycle."
    Write-Error $_
    $_ | FL -force
}

#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Remove-AzureLock.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Remove-AzureLock.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook temporarily removes an Azure Resource Lock

.DESCRIPTION
    This Runbook temporarily removes an Azure Resource Lock
    The lock information will remain in the database.
    At the time specified with the RemovalTimeInMinutes parameter, a Runbook will run to restore the lock to its original settings.

.PARAMETER LockedResourceID
    Provide Resource ID which contains the lock
    Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'

.PARAMETER LockName
    Provide the Name of the lock to remove
    Example: "Key Vault No Delete Lock"

.PARAMETER RemovalTimeInMinutes
    Provide the length of time in minutes before lock is re-enabled
    Example: "60"

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Remove-AzureLock.ps1 `
        -LockedResourceID '/subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault' `
        -LockName 'Key Vault No Delete Lock' `
        -RemovalTimeInMinutes '60'

#>
[CmdletBinding()]
param
(
    # Provide Resource ID which contains the lock
    # Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'
    [parameter(Mandatory=$true,HelpMessage='Provide Resource ID which contains the lock. Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault')]
    [String]$LockedResourceID,

    # Provide the Name of the lock to remove
    # Example: "Key Vault No Delete Lock"
    [parameter(Mandatory=$true,HelpMessage='Provide the Name of the lock to remove. Example: Key Vault No Delete Lock')]
    [String]$LockName,
    
    # Provide the length of time in minutes before lock is re-enabled
    # Example: "60"
    [parameter(Mandatory=$true,HelpMessage='Provide the length of time in minutes before lock is re-enabled. Example: 60')]
    [ValidateRange(20,1440)]
    [Int]$RemovalTimeInMinutes,

    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

# Build Custom Locks Table Filter
$LockID = $LockedResourceID + '/providers/Microsoft.Authorization/locks/' + $LockName
[string]$filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("LockId",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$LockID)

# Get Azure Locks and Locks Table Data
$ResourceLock = Get-AzTableRow -table $cloudTable -customFilter $filter
$AzureResourceLock = Get-AzResourceLock | Where-Object {$_.LockId -eq $($ResourceLock.LockId)}

#region Remove Lock and Update Tables
try
{
    $AzureResourceLock | Remove-AzResourceLock -Force
    $ResourceLock.TimeRemoved = (Get-Date -Format s)
    $ResourceLock.TimeToRestore = (Get-Date).AddMinutes($RemovalTimeInMinutes).GetDateTimeFormats('s')
    $ResourceLock.IsRemoved = 'True'
}
catch
{
    Write-Error "Failed to Remove Resource Lock"
    $_
}
#endregion

#region Create Lock Restore Schedule and Link Restore Runbook
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $StorageAccountResourceGroupName
$RunbookParameters = @{LockedResourceID=$LockedResourceID;LockName=$LockName}
Write-Output "Creating Lock Restore Schedule"
try
{
    $Schedule = New-AzAutomationSchedule -OneTime -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Name $ResourceLock.RowKey -StartTime (([datetime]::Now).AddMinutes($RemovalTimeInMinutes)) -Verbose -ErrorAction 'Stop'
    Register-AzAutomationScheduledRunbook -RunbookName Restore-AzureLock -ScheduleName $Schedule.Name -AutomationAccountName $Schedule.AutomationAccountName -ResourceGroupName $Schedule.ResourceGroupName -Parameters $RunbookParameters -Verbose -ErrorAction 'Stop'
}
catch
{
    Write-Warning $_
}
#endregion

#region Update Lock Table
try
{
    $ResourceLock | Update-AzTableRow -table $cloudTable
}
catch
{
    Write-Error "Failed to update lock table"
    $_
}
#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Restore-AzureLock.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Restore-AzureLock.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to restore an Azure Resource Lock from the database.

.DESCRIPTION
    This Runbook is used to restore an Azure Resource Lock from the database.
    It is scheduled automatically when the Remove-AzureLock Runbook is used.
    The parameters are automatically added to a scheduled run.
    Upon completion the schedule is removed.

.PARAMETER LockedResourceID
    Provide Resource ID which contained the lock
    Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'

.PARAMETER LockName
    Provide the Name of the lock to restore
    Example: "Key Vault No Delete Lock"

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Restore-AzureLock.ps1 `
        -LockedResourceID '/subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault' `
        -LockName 'Key Vault No Delete Lock'
#>
[CmdletBinding()]
param
(
    # Provide Resource ID which contained the lock
    # Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault'
    [parameter(Mandatory=$true,HelpMessage='Provide Resource ID which contained the lock. Example: /subscriptions/e980dd22-04ac-4f49-a186-2218c1787d1b/resourceGroups/Test-RG/providers/Microsoft.KeyVault/vaults/MyVault')]
    [String]$LockedResourceID,

    # Provide the Name of the lock to restore
    # Example: "Key Vault No Delete Lock"
    [parameter(Mandatory=$true,HelpMessage='Provide the Name of the lock to restore. Example: Key Vault No Delete Lock')]
    [String]$LockName,

    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

# Build Custom Locks Table Filter
$LockID = $LockedResourceID + '/providers/Microsoft.Authorization/locks/' + $LockName
[string]$filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("LockId",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$LockID)

# Get Azure Locks and Locks Table Data
$ResourceLock = Get-AzTableRow -table $cloudTable -customFilter $filter

#region Restore Lock and Update Tables
try
{
    New-AzResourceLock -LockLevel $ResourceLock.level -LockName $ResourceLock.Name -Scope $LockedResourceID -LockNotes $ResourceLock.notes -Force
    $ResourceLock.TimeRemoved = 'null'
    $ResourceLock.TimeToRestore = 'null'
    $ResourceLock.IsRemoved = 'False'
    $ResourceLock.IsDeleted = 'False'
}
catch
{
    Write-Error "Failed to Add Resource Lock"
    $_
}
#endregion

#region Update Lock Table
try
{
    $ResourceLock | Update-AzTableRow -table $cloudTable
}
catch
{
    Write-Error "Failed to update lock table"
    $_
}
#endregion

#region Remove Restore Schedule
$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $StorageAccountResourceGroupName
try
{
    $Schedule = Get-AzAutomationSchedule -Name $ResourceLock.RowKey -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
    if ($Schedule)
    {
        Write-Output "Removing Lock Restore Schedule"
        Remove-AzAutomationSchedule -Name $ResourceLock.RowKey -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Force
    }
}
catch
{
    Write-Warning $_
}
#endregion
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Get-DeletedLocks.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Get-DeletedLocks.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to generate a report of deleted locks.

.DESCRIPTION
    This Runbook is used to generate a report of deleted locks.
    Locks marked as deleted will appear in the Runbook Output

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Get-DeletedLocks.ps1
#>
[CmdletBinding()]
param
(
    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $StorageAccountReportsContainerName = Get-AutomationVariable -Name 'ReportsContainer'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $StorageAccountResourceGroupName
Start-AzAutomationRunbook -Name 'Import-AzureLocksToTableStorage' -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Wait

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

# Build Custom Locks Table Filter and Get Locks Table Data
[string]$filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("IsDeleted",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,'True')
$ResourceLocks = Get-AzTableRow -table $cloudTable -customFilter $filter

if ($ResourceLocks.Count -ge '1')
{
    # Create Data Table Structure
    Write-Verbose 'Creating DataTable Structure'
    $DataTable = New-Object System.Data.DataTable
    $DataTable.Columns.Add("Name","string") | Out-Null
    $DataTable.Columns.Add("Description","string") | Out-Null
    $DataTable.Columns.Add("LockId","string") | Out-Null
    $DataTable.Columns.Add("LockLevel","string") | Out-Null
    $DataTable.Columns.Add("ResourceGroupName","string") | Out-Null
    $DataTable.Columns.Add("ResourceType","string") | Out-Null
    $DataTable.Columns.Add("ResourceId","string") | Out-Null
    $DataTable.Columns.Add("DeletedOn","string") | Out-Null

    # Set Counter For Orphaned Objects
    [Int]$DeletedLocksCount = '0'

    foreach ($ResourceLock in $ResourceLocks)
    {
        $ResourceLock.ResourceId = $ResourceLock.LockId.Substring(0, $ResourceLock.LockId.IndexOf('/providers/Microsoft.Authorization/locks'))
        $ResourceLock  | Select-Object Name, Notes, Level, ResourceId, DeletedOn
        $NewRow = $DataTable.NewRow() 
        $NewRow.Name = $($ResourceLock.Name)
        $NewRow.Description = $($ResourceLock.Notes)
        $NewRow.LockLevel = $($ResourceLock.Level)
        $NewRow.LockId = $($ResourceLock.LockId)
        $NewRow.ResourceId = $($ResourceLock.ResourceId)
        $NewRow.DeletedOn = ($ResourceLock.DeletedOn)
        $NewRow.ResourceGroupName = ($ResourceLock.ResourceGroupName)
        $NewRow.ResourceType = ($ResourceLock.ResourceType)
        $DataTable.Rows.Add($NewRow)
        $DeletedLocksCount ++
    }

    Write-Output "I have Found $DeletedLocksCount Deleted Locks."
    # Export the results to CSV file
    $CSVFileName = 'DeletedLocksReport ' + $(Get-Date -f yyyy-MM-dd) + '.csv'
    $DataTable | Export-Csv "$ENV:Temp\$CSVFileName" -NoTypeInformation -Force

    # Copy File to Azure Storage
    Write-Verbose "Uploading Report to $StorageAccountReportsContainerName"
    $StorageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $Containers = Get-AzStorageContainer -Context $StorageAccount.Context
    if ($StorageAccountReportsContainerName -notin $Containers.Name)
    {
        New-AzRMStorageContainer -Name $StorageAccountReportsContainerName -ResourceGroupName $StorageAccountResourceGroupName -StorageAccountName $StorageAccountName
    }

    Set-AzStorageBlobContent -BlobType 'Block' -File "$ENV:Temp\$CSVFileName" -Container $StorageAccountReportsContainerName -Blob "$CSVFileName" -Context $StorageAccount.Context -Force | Out-Null

    # Make file available for download
    Write-Verbose "Generating Download Link"
    $StartTime = Get-Date
    $EndTime = $startTime.AddHours(2.0)
    $DownloadLink = New-AzStorageBlobSASToken -Context $StorageAccount.Context -Container $StorageAccountReportsContainerName -Blob $CSVFileName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop

    Write-Output "Deleted Locks Report can be downloaded until $EndTime from the link below."
    Write-Output "$DownloadLink"

}
else
{
    Write-Verbose 'No deleted locks found'
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion

#region Add Get-AllLocks.ps1 Runbook
$RunbookType = 'PowerShell'
$RunbookFilePath = New-Item -Path "$env:TEMP\Get-AllLocks.ps1" -ItemType File -Force
$RunbookFileContent = @'
<#
.SYNOPSIS
    This Runbook is used to get a list of Locks.

.DESCRIPTION
    This Runbook is used to get a list of Locks.
    All Locks will appear in the report.
    A download link will be provided in the output.

.PARAMETER SubscriptionID
    Provide Target Subscription ID
    Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"

.EXAMPLE
    ./Get-AllLocks.ps1
#>
[CmdletBinding()]
param
(
    # Provide Target Subscription ID
    # Example: "e980dd22-04ac-4f49-a186-2218c1787d1b"
    [parameter(Mandatory=$false,HelpMessage='Example: e980dd22-04ac-4f49-a186-2218c1787d1b')]
    [String]$SubscriptionID
)

# Connect to Azure
try
{
    # Get RunAsConnection
    $RunAsConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'

    Connect-AzAccount -ServicePrincipal `
        -Tenant $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment '[Environment]' `
        -ErrorAction Stop

    # Get Subscription Id if not provided
    if (!$SubscriptionId)
    {
        $SubscriptionId = $RunAsConnection.SubscriptionId
    }
}
catch
{
    Write-Error $_
    $_ | FL -force
}

# Set the Current Working Subscription
$Subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
Set-AzContext $Subscription

#region Get Automation Variables
try
{
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
    $StorageAccountResourceGroupName = Get-AutomationVariable -Name 'StorageAccountResourceGroupName'
    $StorageAccountReportsContainerName = Get-AutomationVariable -Name 'ReportsContainer'
    $TableName = Get-AutomationVariable -Name 'LocksTableName'
    $LocksKey = Get-AutomationVariable -Name 'LocksKey'
}
catch
{
    Write-Error $_
    $_ | FL -force
}
#endregion

$AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $StorageAccountResourceGroupName
Start-AzAutomationRunbook -Name 'Import-AzureLocksToTableStorage' -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Wait

# Get Storage Account and Storage Table Data
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $StorageAccountResourceGroupName -ErrorAction Stop -Verbose
$StorageTable = Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context -ErrorAction Stop -Verbose
$CloudTable = (Get-AzStorageTable -Name $TableName -Context $StorageAccount.Context).CloudTable

# Get Locks Table Data
$ResourceLocks = Get-AzTableRow -table $cloudTable

if ($ResourceLocks.Count -ge '1')
{
    # Create Data Table Structure
    Write-Verbose 'Creating DataTable Structure'
    $DataTable = New-Object System.Data.DataTable
    $DataTable.Columns.Add("Name","string") | Out-Null
    $DataTable.Columns.Add("Description","string") | Out-Null
    $DataTable.Columns.Add("LockId","string") | Out-Null
    $DataTable.Columns.Add("LockLevel","string") | Out-Null
    $DataTable.Columns.Add("ResourceGroupName","string") | Out-Null
    $DataTable.Columns.Add("ResourceType","string") | Out-Null
    $DataTable.Columns.Add("ResourceId","string") | Out-Null
    $DataTable.Columns.Add("DeletedOn","string") | Out-Null

    # Set Counter For Locks
    [Int]$LocksCount = '0'

    foreach ($ResourceLock in $ResourceLocks)
    {
        $ResourceLock.ResourceId = $ResourceLock.LockId.Substring(0, $ResourceLock.LockId.IndexOf('/providers/Microsoft.Authorization/locks'))
        $ResourceLock  | Select-Object Name, Notes, Level, ResourceId, DeletedOn

        $NewRow = $DataTable.NewRow() 
        $NewRow.Name = $($ResourceLock.Name)
        $NewRow.Description = $($ResourceLock.Notes)
        $NewRow.LockLevel = $($ResourceLock.Level)
        $NewRow.LockId = $($ResourceLock.LockId)
        $NewRow.ResourceId = $($ResourceLock.ResourceId)
        $NewRow.DeletedOn = ($ResourceLock.DeletedOn)
        $NewRow.ResourceGroupName = ($ResourceLock.ResourceGroupName)
        $NewRow.ResourceType = ($ResourceLock.ResourceType)

        $DataTable.Rows.Add($NewRow)
        $LocksCount ++
    }

    Write-Output "I have Found $LocksCount Locks."
    # Export the results to CSV file
    $CSVFileName = 'LocksReport ' + $(Get-Date -f yyyy-MM-dd) + '.csv'
    $DataTable | Export-Csv "$ENV:Temp\$CSVFileName" -NoTypeInformation -Force

    # Copy File to Azure Storage
    Write-Verbose "Uploading Report to $StorageAccountReportsContainerName"
    $StorageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    $Containers = Get-AzStorageContainer -Context $StorageAccount.Context
    if ($StorageAccountReportsContainerName -notin $Containers.Name)
    {
        New-AzRMStorageContainer -Name $StorageAccountReportsContainerName -ResourceGroupName $StorageAccountResourceGroupName -StorageAccountName $StorageAccountName
    }

    Set-AzStorageBlobContent -BlobType 'Block' -File "$ENV:Temp\$CSVFileName" -Container $StorageAccountReportsContainerName -Blob "$CSVFileName" -Context $StorageAccount.Context -Force | Out-Null

    # Make file available for download
    Write-Verbose "Generating Download Link"
    $StartTime = Get-Date
    $EndTime = $startTime.AddHours(2.0)
    $DownloadLink = New-AzStorageBlobSASToken -Context $StorageAccount.Context -Container $StorageAccountReportsContainerName -Blob $CSVFileName -Permission r -FullUri -StartTime $StartTime -ExpiryTime $EndTime -ErrorAction Stop

    Write-Output "Locks Report can be downloaded until $EndTime from the link below."
    Write-Output "$DownloadLink"

}
else
{
    Write-Verbose 'No Locks found'
}
'@
Add-Content -Path $RunbookFilePath -Value $RunbookFileContent
(Get-Content $RunbookFilePath.FullName).replace('[Environment]', $Environment) | Set-Content $RunbookFilePath.FullName
try
{
    Write-Output "Importing Runbook $($RunbookFilePath.BaseName)"
    Import-AzAutomationRunbook -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Path $RunbookFilePath.FullName -Type $RunbookType -Verbose -ErrorAction 'Stop'
    Publish-AzAutomationRunbook -Name $($RunbookFilePath.BaseName) -AutomationAccountName $AutomationAccountName -ResourceGroupName $AutomationAccountResourceGroupName -Verbose -ErrorAction 'Stop'
}
catch 
{
    Write-Warning $_
    break
}
#endregion
#endregion

#region Add Az.Storage Module and Dependencies
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "http://schemas.microsoft.org/azure/deploymentTemplate?api-version=2015-01-01#",
    "contentVersion": "1.0",
    "parameters": {
      "New or existing Automation account": {
        "type": "string",
        "allowedValues": [
          "New",
          "Existing"
        ],
        "metadata": {
          "description": "Select whether you want to create a new Automation account or use an existing account. WARNING: if you select NEW but use an Automation account name that already exists in your subscription, you will not be notified that your account is being updated. The pricing tier for the account will be set to free and any tags on the account will be erased."
        },
        "defaultvalue":"Existing"
      },
      "automationAccountName": {
        "type": "string",
        "metadata": {
          "description": "The module will be imported to this Automation account. If you want to import your module to an existing account, make sure the resource group matches and you have entered the correct name. The account name must be between 6 to 50 characters, and can contain only letters, numbers, and hyphens."
        }
      },
      "automationAccountLocation": {
        "type": "string",
        "metadata": {
          "description": "The location to deploy the Automation account in. If you select an existing account, the location field will not be used."
        }
      }
    },
    "variables": {
      "templatelink": "[concat('https://devopsgallerystorage.blob.core.windows.net/armtemplates/Az.Storage/1.14.0/', parameters('New or existing Automation account'), 'AccountTemplate.json')]",
      "Level1": {
        "Modules": [
          {
            "Name": "Az.Accounts",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.accounts.1.7.5.nupkg"
          }
        ]
      },
      "Level0": {
        "Modules": [
          {
            "Name": "Az.Storage",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.storage.1.14.0.nupkg"
          }
        ]
      }
    },
    "resources": [
      {
        "apiVersion": "[providers('Microsoft.Resources','deployments').apiVersions[0]]",
        "name": "nestedTemplate",
        "type": "Microsoft.Resources/deployments",
        "properties": {
          "mode": "incremental",
          "templateLink": {
            "uri": "[variables('templatelink')]",
            "contentVersion": "1.0"
          },
          "parameters": {
            "accountName": {
              "value": "[parameters('automationAccountName')]"
            },
            "accountLocation": {
              "value": "[parameters('automationAccountLocation')]"
            },
            "Level1": {
              "value": "[variables('Level1')]"
            },
            "Level0": {
              "value": "[variables('Level0')]"
            }
          }
        }
      }
    ],
    "outputs": {}
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Az.Storage Module and Dependencies. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Az.Storage Module and Dependencies Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Add Az.Automation Module and Dependencies
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "http://schemas.microsoft.org/azure/deploymentTemplate?api-version=2015-01-01#",
    "contentVersion": "1.0",
    "parameters": {
      "New or existing Automation account": {
        "type": "string",
        "allowedValues": [
          "New",
          "Existing"
        ],
        "metadata": {
          "description": "Select whether you want to create a new Automation account or use an existing account. WARNING: if you select NEW but use an Automation account name that already exists in your subscription, you will not be notified that your account is being updated. The pricing tier for the account will be set to free and any tags on the account will be erased."
        },
        "defaultvalue":"Existing"
      },
      "automationAccountName": {
        "type": "string",
        "metadata": {
          "description": "The module will be imported to this Automation account. If you want to import your module to an existing account, make sure the resource group matches and you have entered the correct name. The account name must be between 6 to 50 characters, and can contain only letters, numbers, and hyphens."
        }
      },
      "automationAccountLocation": {
        "type": "string",
        "metadata": {
          "description": "The location to deploy the Automation account in. If you select an existing account, the location field will not be used."
        }
      }
    },
    "variables": {
      "templatelink": "[concat('https://devopsgallerystorage.blob.core.windows.net/armtemplates/Az.Automation/1.3.6/', parameters('New or existing Automation account'), 'AccountTemplate.json')]",
      "Level1": {
        "Modules": [
          {
            "Name": "Az.Accounts",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.accounts.1.7.5.nupkg"
          }
        ]
      },
      "Level0": {
        "Modules": [
          {
            "Name": "Az.Automation",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.automation.1.3.6.nupkg"
          }
        ]
      }
    },
    "resources": [
      {
        "apiVersion": "[providers('Microsoft.Resources','deployments').apiVersions[0]]",
        "name": "nestedTemplate",
        "type": "Microsoft.Resources/deployments",
        "properties": {
          "mode": "incremental",
          "templateLink": {
            "uri": "[variables('templatelink')]",
            "contentVersion": "1.0"
          },
          "parameters": {
            "accountName": {
              "value": "[parameters('automationAccountName')]"
            },
            "accountLocation": {
              "value": "[parameters('automationAccountLocation')]"
            },
            "Level1": {
              "value": "[variables('Level1')]"
            },
            "Level0": {
              "value": "[variables('Level0')]"
            }
          }
        }
      }
    ],
    "outputs": {}
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Az.Automation Module and Dependencies. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Az.Automation Module and Dependencies Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Add Az.Resources Module and Dependencies
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "http://schemas.microsoft.org/azure/deploymentTemplate?api-version=2015-01-01#",
    "contentVersion": "1.0",
    "parameters": {
      "New or existing Automation account": {
        "type": "string",
        "allowedValues": [
          "New",
          "Existing"
        ],
        "metadata": {
          "description": "Select whether you want to create a new Automation account or use an existing account. WARNING: if you select NEW but use an Automation account name that already exists in your subscription, you will not be notified that your account is being updated. The pricing tier for the account will be set to free and any tags on the account will be erased."
        },
        "defaultvalue":"Existing"
      },
      "automationAccountName": {
        "type": "string",
        "metadata": {
          "description": "The module will be imported to this Automation account. If you want to import your module to an existing account, make sure the resource group matches and you have entered the correct name. The account name must be between 6 to 50 characters, and can contain only letters, numbers, and hyphens."
        }
      },
      "automationAccountLocation": {
        "type": "string",
        "metadata": {
          "description": "The location to deploy the Automation account in. If you select an existing account, the location field will not be used."
        }
      }
    },
    "variables": {
      "templatelink": "[concat('https://devopsgallerystorage.blob.core.windows.net/armtemplates/Az.Resources/1.13.0/', parameters('New or existing Automation account'), 'AccountTemplate.json')]",
      "Level1": {
        "Modules": [
          {
            "Name": "Az.Accounts",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.accounts.1.7.5.nupkg"
          }
        ]
      },
      "Level0": {
        "Modules": [
          {
            "Name": "Az.Resources",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.resources.1.13.0.nupkg"
          }
        ]
      }
    },
    "resources": [
      {
        "apiVersion": "[providers('Microsoft.Resources','deployments').apiVersions[0]]",
        "name": "nestedTemplate",
        "type": "Microsoft.Resources/deployments",
        "properties": {
          "mode": "incremental",
          "templateLink": {
            "uri": "[variables('templatelink')]",
            "contentVersion": "1.0"
          },
          "parameters": {
            "accountName": {
              "value": "[parameters('automationAccountName')]"
            },
            "accountLocation": {
              "value": "[parameters('automationAccountLocation')]"
            },
            "Level1": {
              "value": "[variables('Level1')]"
            },
            "Level0": {
              "value": "[variables('Level0')]"
            }
          }
        }
      }
    ],
    "outputs": {}
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Az.Resources Module and Dependencies. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Az.Resources Module and Dependencies Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Add Az.Profile Module and Dependencies
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "http://schemas.microsoft.org/azure/deploymentTemplate?api-version=2015-01-01#",
    "contentVersion": "1.0",
    "parameters": {
      "New or existing Automation account": {
        "type": "string",
        "allowedValues": [
          "New",
          "Existing"
        ],
        "metadata": {
          "description": "Select whether you want to create a new Automation account or use an existing account. WARNING: if you select NEW but use an Automation account name that already exists in your subscription, you will not be notified that your account is being updated. The pricing tier for the account will be set to free and any tags on the account will be erased."
        },
        "defaultvalue":"Existing"
      },
      "automationAccountName": {
        "type": "string",
        "metadata": {
          "description": "The module will be imported to this Automation account. If you want to import your module to an existing account, make sure the resource group matches and you have entered the correct name. The account name must be between 6 to 50 characters, and can contain only letters, numbers, and hyphens."
        }
      },
      "automationAccountLocation": {
        "type": "string",
        "metadata": {
          "description": "The location to deploy the Automation account in. If you select an existing account, the location field will not be used."
        }
      }
    },
    "variables": {
      "templatelink": "[concat('https://devopsgallerystorage.blob.core.windows.net/armtemplates/Az.Profile/0.7.0/', parameters('New or existing Automation account'), 'AccountTemplate.json')]",
      "Level0": {
        "Modules": [
          {
            "Name": "Az.Profile",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/az.profile.0.7.0.nupkg"
          }
        ]
      }
    },
    "resources": [
      {
        "apiVersion": "[providers('Microsoft.Resources','deployments').apiVersions[0]]",
        "name": "nestedTemplate",
        "type": "Microsoft.Resources/deployments",
        "properties": {
          "mode": "incremental",
          "templateLink": {
            "uri": "[variables('templatelink')]",
            "contentVersion": "1.0"
          },
          "parameters": {
            "accountName": {
              "value": "[parameters('automationAccountName')]"
            },
            "accountLocation": {
              "value": "[parameters('automationAccountLocation')]"
            },
            "Level0": {
              "value": "[variables('Level0')]"
            }
          }
        }
      }
    ],
    "outputs": {}
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Az.Profile Module and Dependencies. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Az.Profile Module and Dependencies Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Add AzTable Module and Dependencies
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "http://schemas.microsoft.org/azure/deploymentTemplate?api-version=2015-01-01#",
    "contentVersion": "1.0",
    "parameters": {
      "New or existing Automation account": {
        "type": "string",
        "allowedValues": [
          "New",
          "Existing"
        ],
        "metadata": {
          "description": "Select whether you want to create a new Automation account or use an existing account. WARNING: if you select NEW but use an Automation account name that already exists in your subscription, you will not be notified that your account is being updated. The pricing tier for the account will be set to free and any tags on the account will be erased."
        },
        "defaultvalue":"Existing"
      },
      "automationAccountName": {
        "type": "string",
        "metadata": {
          "description": "The module will be imported to this Automation account. If you want to import your module to an existing account, make sure the resource group matches and you have entered the correct name. The account name must be between 6 to 50 characters, and can contain only letters, numbers, and hyphens."
        }
      },
      "automationAccountLocation": {
        "type": "string",
        "metadata": {
          "description": "The location to deploy the Automation account in. If you select an existing account, the location field will not be used."
        }
      }
    },
    "variables": {
      "templatelink": "[concat('https://devopsgallerystorage.blob.core.windows.net/armtemplates/AzTable/2.0.3/', parameters('New or existing Automation account'), 'AccountTemplate.json')]",
      "Level0": {
        "Modules": [
          {
            "Name": "AzTable",
            "Uri": "https://devopsgallerystorage.blob.core.windows.net:443/packages/aztable.2.0.3.nupkg"
          }
        ]
      }
    },
    "resources": [
      {
        "apiVersion": "[providers('Microsoft.Resources','deployments').apiVersions[0]]",
        "name": "nestedTemplate",
        "type": "Microsoft.Resources/deployments",
        "properties": {
          "mode": "incremental",
          "templateLink": {
            "uri": "[variables('templatelink')]",
            "contentVersion": "1.0"
          },
          "parameters": {
            "accountName": {
              "value": "[parameters('automationAccountName')]"
            },
            "accountLocation": {
              "value": "[parameters('automationAccountLocation')]"
            },
            "Level0": {
              "value": "[variables('Level0')]"
            }
          }
        }
      }
    ],
    "outputs": {}
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "automationAccountName": {
            "value": "$AutomationAccountName"
        },
        "automationAccountLocation": {
            "value": "$Location"
        }
    }
}
"@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying AzTable Module and Dependencies. This may take a few minutes."
    New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "AzTable Module and Dependencies Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Create Locks Storage Account
$DeploymentJSONFilePath = New-Item -Path "$env:TEMP\azuredeploy.json" -ItemType File -Force
$DeploymentJSONContent = @'
{
    "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
      "storageAccountType": {
        "type": "string",
        "defaultValue": "Standard_LRS",
        "allowedValues": [
          "Standard_LRS",
          "Standard_GRS",
          "Standard_ZRS",
          "Premium_LRS"
        ],
        "metadata": {
          "description": "Storage Account type"
        }
      },
      "location": {
        "type": "string",
        "defaultValue": "[resourceGroup().location]",
        "metadata": {
          "description": "Location for all resources."
        }
      }
    },
    "variables": {
      "storageAccountName": "[concat('store', uniquestring(resourceGroup().id))]"
    },
    "resources": [
      {
        "type": "Microsoft.Storage/storageAccounts",
        "name": "[variables('storageAccountName')]",
        "location": "[parameters('location')]",
        "apiVersion": "[providers('Microsoft.Storage','storageAccounts').apiVersions[0]]",
        "sku": {
          "name": "[parameters('storageAccountType')]"
        },
        "kind": "StorageV2",
        "properties": {
          "supportsHttpsTrafficOnly": true
        }
      }
    ],
    "outputs": {
      "storageAccountName": {
        "type": "string",
        "value": "[variables('storageAccountName')]"
      }
    }
  }
'@
Add-Content -Path $DeploymentJSONFilePath -Value $DeploymentJSONContent

$DeploymentParametersFilePath = New-Item -Path "$env:TEMP\azuredeploy.parameters.json" -ItemType File -Force
$DeploymentParametersJSON = @'
{
    "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": { 
        "storageAccountType":{
            "value":"Standard_LRS"
        }
    }
  }
'@
Add-Content -Path $DeploymentParametersFilePath -Value $DeploymentParametersJSON

try
{
    Write-Output "Deploying Locks Storage Account. This may take a few minutes."
    $Deployment = New-AzResourceGroupDeployment -ResourceGroupName $AutomationAccountResourceGroupName -TemplateFile $($DeploymentJSONFilePath.FullName) -TemplateParameterFile $($DeploymentParametersFilePath.FullName) -ErrorAction 'Stop'
    Write-Output "Locks Storage Account Deployment completed successfully"
}
catch
{
    Write-Warning $_
    break
}
#endregion

#region Create Table Storage and Add Automation Account Variables
$StorageAccountContext = (Get-AzStorageAccount -Name $($Deployment.Outputs.Values.value) -ResourceGroupName $AutomationAccountResourceGroupName).Context
 
New-AzStorageTable –Name resourcelocks –Context $StorageAccountContext -WarningAction Ignore

New-AzAutomationVariable -Name ReportsContainer -Value reports -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false 

New-AzAutomationVariable -Name LocksTableName -Value resourcelocks -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false 

New-AzAutomationVariable -Name LocksKey -Value lockskey -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false 

New-AzAutomationVariable -Name StorageAccountResourceGroupName -Value $AutomationAccountResourceGroupName -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false 

New-AzAutomationVariable -Name StorageAccountName -Value $($Deployment.Outputs.Values.value) -ResourceGroupName $AutomationAccountResourceGroupName -AutomationAccountName $AutomationAccountName -Encrypted $false 
#endregion

