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