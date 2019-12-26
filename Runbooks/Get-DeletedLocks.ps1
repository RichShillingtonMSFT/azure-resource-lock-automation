<#
.SYNOPSIS
    This Runbook is used to display deleted locks.

.DESCRIPTION
    This Runbook is used to display deleted locks.
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
    $DataTable.Columns.Add("LockLevel","string") | Out-Null
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
        $NewRow.ResourceId = $($ResourceLock.ResourceId)
        $NewRow.DeletedOn = ($ResourceLock.DeletedOn)
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