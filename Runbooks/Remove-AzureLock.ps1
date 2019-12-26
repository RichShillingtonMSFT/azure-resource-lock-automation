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