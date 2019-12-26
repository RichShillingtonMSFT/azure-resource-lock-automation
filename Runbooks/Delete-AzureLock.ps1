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
    $_ | Format-List -force
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