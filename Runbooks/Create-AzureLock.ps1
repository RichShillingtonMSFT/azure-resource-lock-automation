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
    $_ | Format-List -force
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