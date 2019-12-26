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