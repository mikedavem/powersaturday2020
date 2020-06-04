[OutputType("PSAzureOperationResponse")]
param
(
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
)
$ErrorActionPreference = "stop"
$WarningPreference = "SilentlyContinue"

Function Invoke-LSSendEmail{
<#
    .SYNOPSIS
        To send email from Azure Automation

    .DESCRIPTION
        Email will be sent from O356 in direct mode

    .PARAMETER SmtpServer
        SMTP Server

    .PARAMETER Port
        SMTP Port

    .PARAMETER UseSSL
        Switch to SSL mode

    .PARAMETER From
        Email sender (must be an email address that doesn't exist or doesn't
        belong to any O365 account)

    .PARAMETER To
        Recipient(s)

    .PARAMETER Subject
        Subject email

    .PARAMETER Body
        Body email
#>
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SmtpServer
        ,
        [Parameter(Mandatory=$true)]
        [Int]$Port
        ,
        [Parameter(Mandatory=$False)]
        [Boolean]$UseSSL=$true
        ,
        [Parameter(Mandatory=$true)]
        [String]$From
        ,
        [Parameter(Mandatory=$true)]
        [String[]]$To
        ,
        [Parameter(Mandatory=$true)]
        [String]$Subject
        ,
        [Parameter(Mandatory=$true)]
        [String]$Body
    )

    ## Define the Send-MailMessage parameters
    $mailParams = @{
        SmtpServer                 = $SmtpServer
        Port                       = $Port
        UseSSL                     = $UseSSL
        #Credential                 = $credential => With direct send no need to use credential
        From                       = $From
        To                         = $To
        Subject                    = $Subject
        Body                       = $Body
        DeliveryNotificationOption = 'OnFailure', 'OnSuccess'
    }

    ## Send the message
    Send-MailMessage @mailParams -BodyAsHtml
}

Function AzureAutomation{
    # Connect to the right subscription
    $AzureAutomationConnectionName = "AzureRunAsConnection"
    $ServicePrincipalConnection = Get-AutomationConnection -Name $AzureAutomationConnectionName

    Connect-AzAccount `
        -ServicePrincipal `
        -ApplicationId $ServicePrincipalConnection.ApplicationId `
        -Tenant $ServicePrincipalConnection.TenantId `
        -CertificateThumbprint $ServicePrincipalConnection.CertificateThumbprint | Out-Null
}

Function GetAzCompliantDBs {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('PROD', 'ACC', 'INT')]
        [String]$Env
    )

    $Compliant_databases = @()

    Switch ($Env){
        'PROD' { $Compliant_databases = @('LeShop_DWH','Logistic_DM', 'SSISDB')              }
        'ACC'  { $Compliant_databases = @('LeShop_DWH','Logistic_DM', 'SSISDB') }
        'INT'  { $Compliant_databases = @('LeShop_DWH','Logistic_DM', 'SSISDB') }
    }

    $Compliant_databases
}

Function CheckAzSQLServerAdmin{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        [String]$ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [String]$AADAdmin
    )

    $check = ''

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    $Admin = Get-AzSqlServerActiveDirectoryAdministrator `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName

    If ($Admin.DisplayName  -ne $AADAdmin){
        $Check += "Active Directory Admin should be $AADAdmin for Server: $serverName - Found  $($Admin.DisplayName) `n"
    }

    $Check
}

Function CheckAzSQLServerFirewall{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    $Compliant_rules = @('LeShopPublicEcu', 'LeShopPublicDC', 'AllowAllWindowsAzureIps')
    $Check = ''

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    Get-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName | ForEach-Object {
        If ($_.FirewallRuleName -notin $Compliant_rules){
            $Check += "Server Firewall rule should only contains LeShop DC Ips - Found  $($_.FirewallRuleName) - [$($_.StartIpAddress) - $($_.EndIpAddress)] `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}

Function CheckAzSQLServerADS{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        $ServerName
    )

    $Check = ''
    $compliant_ADS_state = 'Enabled'

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    $ADS = Get-AzSqlServerAdvancedDataSecurityPolicy `
            -ResourceGroupName $ResourceGroupName `
            -ServerName $serverName

    If ($ADS.IsEnabled -ne $compliant_ADS_state){
        $Check += "Advanced Data Security should be $compliant_ADS_state for Server: $serverName - Found $($ADS.IsEnabled) `n"
    }

    $Check
}

Function CheckAzSQLServerAdvancedThreat{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$false)]
        [String]$DatabaseName
    )

    $Check = ''

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    $AdvancedThreatDatabaseState = 'Disabled'
    $AdvancedThreatServerState = 'Enabled'

    If ($DatabaseName){
        $AdvancedThreat = Get-AzSqlDatabaseAdvancedThreatProtectionSetting `
                            -ResourceGroupName $ResourceGroupName `
                            -ServerName $serverName `
                            -DatabaseName $DatabaseName

        If ($AdvancedThreat.ThreatDetectionState -ne $AdvancedThreatDatabaseState){
            $Check += "Advanced Threat Detection should be $AdvancedThreatDatabaseState for DB: $DatabaseName - Found $($AdvancedThreat.ThreatDetectionState) `n"
        }
    }
    Else{
        $AdvancedThreat = Get-AzSqlServerAdvancedThreatProtectionSetting `
                            -ResourceGroupName $ResourceGroupName `
                            -ServerName $serverName

        If ($AdvancedThreat.ThreatDetectionState -ne $AdvancedThreatServerState){
            $Check += "Advanced Threat Detection should be $AdvancedThreatServerState for Server: $serverName - Found $($AdvancedThreat.ThreatDetectionState) `n"
        }
    }

    $Check
}

Function CheckAzSQLServerTDE{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
    )

    $Check = ''

    $compliant_tde_state = 'ServiceManaged'

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    $TDE = Get-AzSqlServerTransparentDataEncryptionProtector `
            -ResourceGroupName $ResourceGroupName `
            -ServerName $serverName

    If ($TDE.Type -ne $compliant_tde_state){
        $Check += "TDE Tye should be $compliant_tde_state for Server: $serverName - Found $($TDE.Type) `n"
    }

    $Check
}

Function CheckAzSQLServerAudit{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$true)]
        [String]$omsId
    )

    $check = ''

    $Compliant_audit_state = 'Enabled'
    $Compliant_audit_events = @('SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP', 'FAILED_DATABASE_AUTHENTICATION_GROUP', 'BATCH_COMPLETED_GROUP','DATABASE_PERMISSION_CHANGE_GROUP','DATABASE_PRINCIPAL_CHANGE_GROUP','DATABASE_ROLE_MEMBER_CHANGE_GROUP','USER_CHANGE_PASSWORD_GROUP')

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    $Audit = Get-AzSqlServerAudit `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $serverName

    If (($Audit.LogAnalyticsTargetState -ne $Compliant_audit_state) -and ($Audit.EventHubTargetState -and $Compliant_audit_state) -and ($Audit.BlobStorageTargetState -ne $Compliant_audit_state)){
        $check += "Server audit for Server $serverName should be $Compliant_audit_state - Found Disabled `n"
    }

    If ($Audit.WorkspaceResourceId -ne $omsId){
        $AuditWorkspaceResourceIdShort = "../$($Audit.WorkspaceResourceId.Split('/')[2])/../$($Audit.WorkspaceResourceId.Split('/')[4])/../../../$($Audit.WorkspaceResourceId.Split('/')[8])"
        $omsIdShort = "../$($omsId.Split('/')[2])/../$($omsId.Split('/')[4])/../../../$($omsId.Split('/')[8])"
        $check += "Server audit target for Server $serverName should be $omsIdShort - Found $AuditWorkspaceResourceIdShort `n"
    }

    If (Compare-Object -ReferenceObject $audit.AuditActionGroup -DifferenceObject $Compliant_audit_events){
        $check += "Server audit action group for Server $serverName should contains only $Compliant_audit_events - Found $($Audit.AuditActionGroup) `n"
    }

    $Check
}

Function CheckAzSQLServer{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        [String]$ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$true)]
        [String]$AADAdmin
        ,
        [Parameter(Mandatory=$true)]
        [String]$omsId
    )

    $Check = ''

    $compliant_failovergroup_state = 'Disabled'
    $compliant_autoexecute_status = 'Disabled'

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    # Check TDE configuration
    $Check = CheckAzSQLServerTDE `
                -SubId $SubId `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $serverName

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check SQL Server audits
    $check += CheckAzSQLServerAudit `
        -SubId $SubId `
        -ResourceGroupName $ResourceGroupName `
        -ServerName $serverName `
        -omsId $omsId

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check if exists failoverGroup
    $failoverGroups = Get-AzSqlDatabaseFailoverGroup `
                        -ResourceGroupName $ResourceGroupName `
                        -ServerName $serverName

    If ($failoverGroups){
        ($failoverGroups).ForEach{
            $Check += "Failover Group should be disabled for Server: $serverName - Found $($PSItem.FailoverGroupName) `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check if Elastic Pool exists
    $ElasticPools =  Get-AzSqlElasticPool `
                        -ResourceGroupName $ResourceGroupName `
                        -ServerName $serverName

    If ($ElasticPools){
        ($ElasticPools).ForEach{
            $Check += "Elastic Pool should be disabled for Server: $serverName - Found $($PSItem.ElasticPoolName) `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check SQL Server AAD admin
    $Check = CheckAzSQLServerAdmin `
                -SubId $SubId `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName `
                -AADAdmin $AADAdmin

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check Data Security State
    $check = CheckAzSQLServerADS `
                -SubId $SubId `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $serverName

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check Advanced Threat State
    $check = CheckAzSQLServerAdvancedThreat `
                -SubId $SubId `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $serverName

    If ($Check){
        $Check += "===================================================================== `n"
    }

    # Check Automatic Tuning State
    $AutomaticTuning = Get-AzSqlServerAdvisor `
                        -ResourceGroupName $ResourceGroupName `
                        -ServerName $serverName | Where-Object { $_.AdvisorStatus -eq "GA" }

    ($AutomaticTuning).ForEach{

        If ($PSItem.AutoExecuteStatus -ne $compliant_autoexecute_status){
            $Check += "Automatic tuning - $($PSItem.AdvisorName) should be $compliant_autoexecute_status for Server: $serverName - Found $($PSItem.AutoExecuteStatus) `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}


Function CheckAzDatabase{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$false)]
        [String]$DatabaseName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateSet('All','DB','TDE')]
        [String]$DBCheck='All'
    )

    $Check = ''

    $compliant_databases = $(GetAzCompliantDBs -Env "PROD")
    $compliant_service_objective = @('S','GP_S_Gen5')
    $compliant_tde_state = 'Enabled'

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    If ($DatabaseName){
        $Databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -eq $DatabaseName }
    }
    Else{
        $Databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -ne 'master' }
    }

    If ($null -eq $Databases){
        Write-Error "Database: $DatabaseName is not part of existing Azure SQL Databases"
    }

    # Check if database is in authorized databases on the server
    # Check if database service objective is compliant to LeShop standard
    # Check if database is encrypted
    :FirstLoop Foreach ($DB in ($Databases | Where-Object { $_.DatabaseName -ne 'master' }))
    {
        If ($DBCheck -in ('All', 'DB')){
            If ($DB.DatabaseName -notin $Compliant_databases){
                $Check += "New DB found : $($DB.DatabaseName) - Objective: $($DB.CurrentServiceObjectiveName) - Edition: $($DB.Edition) - CreateDate: $($DB.CreationDate) `n"
            }
        }

        If ($DBCheck -in ('All', 'TDE')){
            $TDE = Get-AzSqlDatabaseTransparentDataEncryption `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName `
                -DatabaseName $DB.DatabaseName

            If ($TDE.State -ne $compliant_tde_state){
                $Check += "Encryption for DB: $($DB.DatabaseName) should be $compliant_tde_state - Found TDE state: $($TDE.State) `n"
            }
        }

        If ($DBCheck -in ('All', 'DB')){
            $verif = $false
            $compliant_service_objective | ForEach-Object{
                If ($DB.RequestedServiceObjectiveName -like "$_*"){
                    $verif = $true
                    Continue FirstLoop
                }
            }

            If (!($verif)){
                $Check += "Service Objective for DB: $($DB.DatabaseName) should be in $compliant_service_objective - Found $($DB.RequestedServiceObjectiveName) `n"
            }
        }

    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}

Function CheckAzDatabaseBackup{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$false)]
        [String]$DatabaseName
    )

    $Check = ''

    $Compliant_databases = $(GetAzCompliantDBs -Env "PROD")

    $Compliant_pitr_critical_dbs = 21
    $Compliant_pitr_noncritical_dbs = 7
    $Compliant_pitr_NewDB = 7
    $Compliant_litr_Weekly = 'PT0S'
    $Compliant_litr_Monthly = 'PT0S'
    $Compliant_litr_Yearly = 'PT0S'
    $Compliant_litr_WeekOfYear = 0

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    If ($DatabaseName){
        $databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -eq $DatabaseName }
    }
    Else{
        $Databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -ne 'master' }
    }

    If ($null -eq $Databases){
        Write-Error "Database: $DatabaseName is not part of existing Azure SQL Databases"
    }

    $databases |  Where-Object { $_.DatabaseName -ne 'master' } | `
    ForEach-Object {
        $pitr = Get-AzSqlDatabaseBackupShortTermRetentionPolicy `
                    -ResourceGroupName $ResourceGroupName `
                    -ServerName $ServerName `
                    -DatabaseName $_.DatabaseName

        $ltr = Get-AzSqlDatabaseBackupLongTermRetentionPolicy `
            -ResourceGroupName $ResourceGroupName `
            -ServerName $ServerName `
            -DatabaseName $_.DatabaseName

        If ($_.DatabaseName -in $Compliant_databases){
            If ($pitr.RetentionDays -notin ($Compliant_pitr_critical_dbs,$Compliant_pitr_noncritical_dbs )){
                $Check += "Backup pitr for DB: $($pitr.DatabaseName) should be $Compliant_pitr - Found $($pitr.RetentionDays) `n"
            }
        }
        Else{
            If ($pitr.RetentionDays -ne $Compliant_pitr_NewDB){
                $Check += "Backup pitr for new DB: $($pitr.DatabaseName) should be $Compliant_pitr_NewDB - Found $($pitr.RetentionDays) `n"
            }
        }

        If (($ltr.WeeklyRetention -ne $Compliant_litr_Weekly) `
            -Or ($ltr.MonthlyRetention -ne $Compliant_litr_Monthly) `
            -Or ($ltr.YearlyRetention -ne $Compliant_litr_Yearly) `
            -or ($ltr.WeekOfYear -ne $Compliant_litr_WeekOfYear)){
                $Check += "Backup ltr for DB: $($_.DatabaseName) should be disabled - Found $($ltr.WeeklyRetention) (W) / $($ltr.MonthlyRetention) (M) / $($ltr.YearlyRetention) (Y) / $($ltr.WeekOfYear) (WF) `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}



Function CheckAzSQLDBAudit{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$false)]
        [String]$DatabaseName
    )

    $check = ''
    $Compliant_audit_state = 'Disabled'

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    If ($DatabaseName){
        $databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -eq $DatabaseName }
    }
    Else{
        $Databases = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -ne 'master' }
    }

    If ($null -eq $Databases){
        Write-Error "Database: $DatabaseName is not part of existing Azure SQL Databases"
    }

    $databases |  Where-Object { $_.DatabaseName -ne 'master' } | `
    ForEach-Object {
        $Audit = Get-AzSqlDatabaseAudit `
                    -ServerName $ServerName `
                    -DatabaseName $_.DatabaseName `
                    -ResourceGroupName $ResourceGroupName

        If (($Audit.LogAnalyticsTargetState -ne $Compliant_audit_state) -or ($Audit.EventHubTargetState -ne $Compliant_audit_state) -or ($Audit.BlobStorageTargetState -ne $Compliant_audit_state)){
            $check += "Database audit for DB: $($_.DatabaseName) should be $Compliant_audit_state - Found AuditActionGroup: {$($Audit.AuditActionGroup)} - AuditAction: {$($Audit.AuditAction)} `n"
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}

Function CheckAzOrphanAlerts{
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubId
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$false)]
        [String]$DatabaseName
    )

    $check = ''

    Select-AzSubscription -SubscriptionName $SubId | Out-Null

    # Used with Delete Database event only
    If ($DatabaseName){
        (Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -like "$ServerName-DB-$DatabaseName-*" } | Select-Object Name).ForEach{
            $Check += "Orphan alerts found $($PsItem.Name) `n"
        }
    }
    Else{
        $DBs = Get-AzSqlDatabase `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName | Select-Object DatabaseName

        $alerts = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -notlike '*-Administrative-ops'} | Select-Object Name
        $pattern = "(?<=-DB-)(.*)(?=-)"
        $alertsDBs = @()

        #Orphan alerts
        ($alerts).ForEach{
            $DB = [regex]::Match($PSItem.Name,$pattern).Groups[1].Value

            $alertsDBs += $DB

            If ($DB -notin $DBs.DatabaseName){
                $Check += "Orphan alerts found $($PsItem.Name) `n"
            }
        }

        # DBs with missing alerts
        ($DBs).Foreach{
            If ($PSItem.DatabaseName -notin $alertsDBs){
                $Check += "DB: $($PSItem.DatabaseName)  found with no alerts `n"
            }
        }
    }

    If ($Check){
        $Check += "===================================================================== `n"
    }

    $Check
}

# ===============================================================#
# Connect with Azure Automation account
AzureAutomation

# Get SQL resource info from PROD Key Vault
$KeyvaultName = "azkv01p"
$SubId = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "SUB-ID").SecretValueText
$AzSQLRGSource = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQL-RG").SecretValueText
$AzSQLNameSource = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQL-NAME").SecretValueText
$AzSQLAADAdmin = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "SQLDB-AAD-ADMIN").SecretValueText
$omsId = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "OMS-BI-ID").SecretValueText
$tenantName = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "TENANT-ID").SecretValueText
$clientId = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQLSPwshAppId").SecretValueText
$clientSecret =  ConvertTo-SecureString (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQLSPwshAppSecret").SecretValueText -AsPlainText -Force


# ===============================================================#
if ($WebhookData)
{
    # Logic to allow for testing in test pane
    If (-Not $WebhookData.RequestBody){
        $WebhookData = (ConvertFrom-Json -InputObject $WebhookData)
    }

    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    Write-Output $WebhookData.RequestBody

    $schemaId = $WebhookBody.schemaId
    #Write-Output "schemaId: $schemaId"

    if ($schemaId -eq "azureMonitorCommonAlertSchema") {
        # This is the common Metric Alert schema (released March 2019)
        $Essentials = [object] ($WebhookBody.data).essentials
        # Get the first target only as this script doesn't handle multiple
        $status = $Essentials.monitorCondition


        if ($status -eq "Succeeded")
        {
            # ($status -eq "Activated") -or ($status -eq "Fired") -or ($status -eq "Started"))
            $alertTargetIdArray = (($Essentials.alertTargetIds)[0]).Split("/")
            $SubId = ($alertTargetIdArray)[2]
            $ResourceGroupName = ($alertTargetIdArray)[4]
            $ResourceType = ($alertTargetIdArray)[6] + "/" + ($alertTargetIdArray)[7]

            Write-Output "subscriptionId: $SubId"
            Write-Output "resourceGroupName: $ResourceGroupName"
            Write-Output "resourceType: $ResourceType"

            # Determine code path depending on the resourceType
            if ($ResourceType -eq "microsoft.sql/servers")
            {
                Write-Output "This is a SQL Server Resource."

                $firedDate = $Essentials.firedDateTime
                $AlertContext = [object] ($WebhookBody.data).alertContext
                $channel = $AlertContext.channels
                $EventSource = $AlertContext.eventSource
                $Level = $AlertContext.level
                $Operation = $AlertContext.operationName

                $Properties = [object] ($WebhookBody.data).alertContext.properties
                $EventName = $Properties.eventName
                $EventStatus = $Properties.status
                $Description = $Properties.description_scrubbed
                $Caller = $Properties.caller
                $IPAddress = $Properties.ipAddress
                $ResourceName = ($alertTargetIdArray)[8]
                $DatabaseName = ($alertTargetIdArray)[10]
                $Operation_detail = $Operation.Split('/')

                Write-Output "FiredDateTime  :  $firedDate"
                Write-Output "Channel        :  $channel"
                Write-Output "Event Source   :  $EventSource"
                Write-Output "Level          : $Level"
                Write-Output "Operation      : $Operation"
                Write-Output "EventName      : $EventName"
                Write-Output "EventStatus    : $EventStatus"
                Write-Output "Description    : $Description"
                Write-Output "Caller         : $Caller "
                Write-Output "IPAddress      : $IPAddress "
                Write-Output "Resource       : $($Operation_detail[2])"
                Write-Output "Type Operation : $($Operation_detail[3])"
                Write-Output "ResourceName   : $ResourceName"
                Write-Output "DatabaseName   : $DatabaseName"

                # Check firewall rules
                If ($EventName -eq 'OverwriteFirewallRules'){
                    Write-Output "Firewall Overwrite is detected ..."

                    $ResourceName = ($alertTargetIdArray)[-1]
                    Write-Output "resourceName: $ResourceName"

                    $check = CheckAzSQLServerFirewall `
                                -SubId $SubId `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ResourceName

                    If ($check){
                        $Subject = "$ResourceName - firewall update with incompliant rule(s)"
                        $body = $check -replace "`n", '<br />'
                        $body += "<br />Action initiated by: $Caller - From:  $IPAddress"

                        Write-Output $Subject
                        Write-Output $body
                    }
                }
                Elseif ($EventName -eq 'UpdateDatabase') {
                    Write-Output "Azure Database updated is detected ..."
                    Write-Output $Description

                    $check = CheckAzDatabase `
                                -SubId $SubId `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ResourceName `
                                -DatabaseName $DatabaseName `
                                -DBCheck "DB"

                    If ($check){
                        $Subject = "$ResourceName - $DatabaseName - DB update with incompliant items"
                        $body = $check -replace "`n", '<br />'
                        $body += "<br />Updated initiated by: $Caller - From:  $IPAddress"

                        Write-Output $Subject
                        Write-Output $body
                    }
                }
                Elseif ($EventName -eq 'CreateDatabase'){
                    Write-Output "Azure Database creation has been detected ..."
                    Write-Output $Description

                    $Subject = "$ResourceName - New database: $DatabaseName has been created"
                    $body = $check -replace "`n", '<br />'
                    $body += "<br />Action initiated by: $Caller - From:  $IPAddress"

                    Write-Output $Subject
                    Write-Output $body
                }
                Elseif ($EventName -eq 'DeleteDatabase') {
                    Write-Output "Azure Database has been deleted ..."
                    Write-Output $Description

                    $check = CheckAzOrphanAlerts `
                                -SubId $SubId `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ResourceName `
                                -DatabaseName $DatabaseName `

                    $Subject = "Orphan alerts have been detected"
                    $body = $check -replace "`n", '<br />'
                    $body += "<br />Action initiated by: $Caller - From:  $IPAddress"

                    Write-Output $Subject
                    Write-Output $body
                }
                Elseif ($Operation -eq 'Microsoft.Sql/servers/databases/transparentDataEncryption/write') {
                    Write-Output "Azure Database Encryption update is detected ..."
                    Write-Output $Description

                    $IPAddress = $AlertContext.httpRequest
                    $Caller = $AlertContext.Caller
                    $scope = $AlertContext.authorization.scope.Split('/')
                    $ResourceName = ($scope)[8]
                    $DatabaseName = ($scope)[10]
                    $AlertContext.httpRequest
                    $pattern = "`"clientIpAddress`":`"(.*?)`",`"method"
                    $IPAddress= [regex]::Match($AlertContext.httpRequest,$pattern).Groups[1].Value
                    Write-Output "Caller: $Caller"
                    Write-Output "IP Address: $IPAddress"
                    Write-Output "resourceName: $ResourceName"
                    Write-Output "DatabaseName: $DatabaseName"

                    $check = CheckAzDatabase `
                                -SubId $SubId `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ResourceName `
                                -DatabaseName $DatabaseName `
                                -DBCheck "TDE"

                    $check
                }
                Elseif ($Operation -eq 'Microsoft.Sql/servers/databases/transparentDataEncryption/write') {

                }
                Else {
                    Write-Output "Event not managed yet"
                    Write-Output "Event      : $EventName"
                    Write-Output "Description: $Description"
                }
            }
            else {
                # ResourceType not supported
                Write-Error "$ResourceType is not a supported resource type for this runbook."
            }
        }
        else {
            # The alert status was not 'Activated' or 'Fired' so no action taken
            Write-Verbose ("No action taken. Alert status: " + $status) -Verbose
        }
    }
}
else {
    Write-Output "No Webhook detected ... switch to normal mode ..."

    Write-Output "Check Az SQL Server Firewall Rules ..."
    $check = CheckAzSQLServerFirewall `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource

    Write-Output "Check Az SQL Server configuration ..."
    $check += CheckAzSQLServer `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource `
                -AADAdmin $AzSQLAADAdmin `
                -omsId $omsId

    Write-Output "Check Az Database configuration ..."
    $check += CheckAzDatabase `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource

    Write-Output "Check Az Database backup policies ..."
    $check += CheckAzDatabaseBackup `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource

    Write-Output "Check Az SQL Server audits ..."
    Write-Output "Oms Id: $omsId"


    Write-Output "Check Az Database audits ..."
    $check += CheckAzSQLDBAudit `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource

     Write-Output "Check Az orphan alerts ..."
    $check += CheckAzOrphanAlerts `
                -SubId $SubId `
                -ResourceGroupName $AzSQLRGSource `
                -ServerName $AzSQLNameSource

    If ($check){
        $Subject = "$ResourceName - Incompliant items found"
        $body = $check -replace "`n", '<br />'
    }

    Write-Output $Subject
    Write-Output $body

    # Error
   # Write-Error "This runbook is meant to be started from an Azure alert webhook only."
}