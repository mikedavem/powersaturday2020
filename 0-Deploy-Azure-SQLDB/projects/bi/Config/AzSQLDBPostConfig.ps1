Function Set-AzServerConfig{
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
        [String]$omsId
        ,
        [Parameter(Mandatory=$true)]
        [String]$ADSRecipientsEmails
        ,
        [Parameter(Mandatory=$true)]
        [String]$ADSGroupResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ADSStorageaccountName
        ,
        [Parameter(Mandatory=$true)]
        [String]$AlertActionGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$AlertActionGroupResourceGroupName
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipAudit
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipTDE
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipAutomaticTuning
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipAlerts
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipADS
    )

    $WarningPreference = "SilentlyContinue"

    Select-AzSubscription -SubscriptionName $SubId | Out-Null
    $SubId = (Get-AzSubscription -SubscriptionName $SubId).SubscriptionId

    Try {
        If (-Not $SkipAudit.IsPresent){
            # Configure Server Audit => Log analytics target not handled by Terraform
            $AuditActionGroup = @('SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP', 'FAILED_DATABASE_AUTHENTICATION_GROUP', 'BATCH_COMPLETED_GROUP', 'DATABASE_PERMISSION_CHANGE_GROUP', 'DATABASE_PRINCIPAL_CHANGE_GROUP', 'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 'USER_CHANGE_PASSWORD_GROUP')

            Write-Host "[Azure SqlServer Config]" -NoNewline -ForegroundColor Yellow
            Write-Host "Audit " -NoNewline

            Set-AzSqlServerAudit `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $serverName `
                -AuditActionGroup $AuditActionGroup `
                -LogAnalyticsTargetState Enabled `
                -WorkspaceResourceId $omsId | Out-Null

            Write-Host "configured successfully" -ForegroundColor Green
        }


        
        # Firewall and virtual network handled by Terraform

        If (-Not $SkipTDE.IsPresent){
            # TDE method => Self Managed
            Write-Host "[Azure SqlServer Config]" -NoNewline -ForegroundColor Yellow
            Write-Host "TDE " -NoNewline

            Set-AzSqlServerTransparentDataEncryptionProtector `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $ServerName `
                -Type ServiceManaged | Out-Null

            Write-Host "configured successfully" -ForegroundColor Green
        }

        If (-Not $SkipAutomaticTuning.IsPresent){
        # Automatic Tuning => Disabling ForceLastGoodPlan | DropIndex | CreateIndex
            Write-Host "[Azure SqlServer Config]" -NoNewline -ForegroundColor Yellow
            Write-Host "Automatic Tuning " -NoNewline

            Set-AzSqlServerAdvisorAutoExecuteStatus `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $SqlServer `
                -AdvisorName ForceLastGoodPlan `
                -AutoExecuteStatus Disabled | Out-Null

            Set-AzSqlServerAdvisorAutoExecuteStatus `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $SqlServer `
                -AdvisorName DropIndex `
                -AutoExecuteStatus Disabled | Out-Null

            Set-AzSqlServerAdvisorAutoExecuteStatus `
                -ResourceGroupName $ResourceGroupName `
                -ServerName $SqlServer `
                -AdvisorName CreateIndex `
                -AutoExecuteStatus Disabled | Out-Null

            Write-Host "configured successfully" -ForegroundColor Green
        }

        If (-Not $SkipADS.IsPresent){
            # ADS
            Write-Host "[Azure SqlServer Config]" -NoNewline -ForegroundColor Yellow
            Write-Host "Advanced Data Security " -NoNewline

            $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ADSGroupResourceGroupName -Name $ADSStorageaccountName

            If ($StorageAccount){
                Enable-AzSqlServerAdvancedThreatProtection `
                    -ResourceGroupName $ResourceGroupName `
                    -ServerName $SqlServer | Out-Null

                Update-AzSqlServerAdvancedThreatProtectionSetting `
                    -ResourceGroupName $ResourceGroupName `
                    -ServerName $SqlServer `
                    -NotificationRecipientsEmails $ADSRecipientsEmails | Out-Null

                Write-Host "configured successfully" -ForegroundColor Green
            }
            Else {
                Write-Host "KO - ADS Storage Account not found" -ForegroundColor Red
            }
        }

        If (-Not $SkipAlerts.IsPresent){
            # Alerts
            # Monitor Administrative operations (all databases)

            $alert_name = "$SqlServer-DB-Administrative-ops"

            Write-Host "[Azure SqlServer Config]" -NoNewline -ForegroundColor Yellow
            Write-Host "Alert $alert_name " -NoNewline

            $alert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -eq $alert_name }
            If ($alert) {
                Write-Host "already exists" -ForegroundColor Green
            }
            Else{
                $actiongroup1 = Get-AzActionGroup -ResourceGroup $AlertActionGroupResourceGroupName -Name $AlertActionGroupName

                If ($actiongroup1){
                    #$actiongroup2 = Get-AzActionGroup -ResourceGroup $ResourceGroupName -Name 'notif-DBA'
                    $scope = "/subscriptions/$SubId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$SqlServer/databases"
                    $condition1 = New-AzActivityLogAlertCondition -Field 'category' -Equal 'Administrative'
                    $condition2 = New-AzActivityLogAlertCondition -Field 'level' -Equal 'Informational'
                    $condition3 = New-AzActivityLogAlertCondition -Field 'status' -Equal 'Succeeded'

                    Set-AzActivityLogAlert `
                        -Location 'Global' `
                        -Name $alert_name  `
                        -ResourceGroupName $ResourceGroupName `
                        -Scope $scope `
                        -Action (New-Object Microsoft.Azure.Management.Monitor.Models.ActivityLogAlertActionGroup $actiongroup1.Id) `
                        -Condition $condition1, $condition2, $condition3 `
                        -Description 'Get all SQL Administration events and check if misconfigured / unwanted items exist' | Out-Null

                    Write-Host "created successfully" -ForegroundColor Green
                }
                Else {
                    Write-Host "KO - Action Group not Found" -ForegroundColor Red
                }
            }
        }

    }
    Catch{
        Write-Host "KO" -ForegroundColor Red
        Write-Host $PSItem.Exception.InnerException -ForegroundColor Red
    }
}

Function Set-AzDatabaseConfig{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$SubName
        ,
        [Parameter(Mandatory=$true)]
        $ResourceGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$ServerName
        ,
        [Parameter(Mandatory=$true,ValueFromPipeline=$True)]
        [String[]]$DatabaseName
        ,
        [Parameter(Mandatory=$false)]
        [String[]]$CriticalDBs
        ,
        [Parameter(Mandatory=$true)]
        [String]$AlertActionGroupName
        ,
        [Parameter(Mandatory=$true)]
        [String]$AlertActionGroupResourceGroupName
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipTDE
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipBackupPolicies
        ,
        [Parameter(Mandatory=$false)]
        [Switch]$SkipAlerts
    )

    Begin {
        $WarningPreference = "SilentlyContinue"

        Select-AzSubscription -SubscriptionName $SubName | Out-Null
        $SubId = (Get-AzSubscription -SubscriptionName $SubName).SubscriptionId

        $pitr_retention_policy_Critical_DBs = 21
        $pitr_retention_policy_NonCritical_DBs = 7
        $tde_state_compliant = 'Enabled'
    }
    Process{
        Foreach ($DB in $DatabaseName){
            Try{
                Write-Host "[Azure Database Config]" -NoNewline -ForegroundColor Yellow
                Write-Host "==> Database $DB " -NoNewline

                If (-Not (Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName | Where-Object { $_.DatabaseName -eq $DB })){
                    Write-Host "doesn't exist ... skip next steps" -ForegroundColor Red
                }
                Else {
                    Write-Host "exists ... go to next steps" -ForegroundColor Green
                    If (-Not $SkipTDE.IsPresent){
                        # Enabled TDE
                        Write-Host "[Azure Database Config]" -NoNewline -ForegroundColor Yellow
                        Write-Host "TDE " -NoNewline

                        Set-AzSqlDatabaseTransparentDataEncryption `
                            -ResourceGroupName $ResourceGroupName `
                            -ServerName $ServerName `
                            -DatabaseName $DB `
                            -State $tde_state_compliant | Out-Null

                        Write-Host "configured successfully" -ForegroundColor Green
                    }

                    If (-Not $SkipBackupPolicies.IsPresent){
                        # Configure Backup PITR policy
                        Write-Host "[Azure Database Config]" -NoNewline -ForegroundColor Yellow
                        Write-Host "Backup PITR/LTR " -NoNewline

                        If ($DatabaseName -in $CriticalDBs){
                            Set-AzSqlDatabaseBackupShortTermRetentionPolicy `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ServerName `
                                -DatabaseName $DB `
                                -RetentionDays $pitr_retention_policy_Critical_DBs `
                                -Confirm:$false | Out-Null
                        }
                        Else {
                            Set-AzSqlDatabaseBackupShortTermRetentionPolicy `
                                -ResourceGroupName $ResourceGroupName `
                                -ServerName $ServerName `
                                -DatabaseName $DB `
                                -RetentionDays $pitr_retention_policy_NonCritical_DBs `
                                -Confirm:$false | Out-Null
                        }

                        # Disable Backup LTR policy
                        Set-AzSqlDatabaseBackupLongTermRetentionPolicy `
                            -ResourceGroupName $ResourceGroupName `
                            -ServerName $ServerName `
                            -DatabaseName $DB `
                            -RemovePolicy `
                            -Confirm:$false | Out-Null

                        Write-Host "configured successfully" -ForegroundColor Green
                    }

                    # ADS (Not enabled as the database level)
                    # Configure Automatic Tuning (Inherit from Server)

                    If (-Not $SkipAlerts.IsPresent){
                        # Create alerts
                        $actiongroup = Get-AzActionGroup -ResourceGroup $AlertActionGroupResourceGroupName -Name $AlertActionGroupName

                        If ($actiongroup){
                            $alert_name = "$ServerName-DB-$DB-Encryption"

                            Write-Host "[Azure Database Config]" -NoNewline -ForegroundColor Yellow
                            Write-Host "Alert: $alert_name " -NoNewline

                            $alert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -eq $alert_name }
                            If ($alert) {
                                Write-Host "already exists" -ForegroundColor Green
                            }
                            Else{
                                # Monitor TDE changes
                                $scope = "/subscriptions/$SubId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName/databases/$DB/transparentDataEncryption/current"
                                $condition1 = New-AzActivityLogAlertCondition -Field 'category' -Equal 'Administrative'
                                $condition2 = New-AzActivityLogAlertCondition -Field 'level' -Equal 'Informational'
                                $condition3 = New-AzActivityLogAlertCondition -Field 'status' -Equal 'Succeeded'

                                Set-AzActivityLogAlert `
                                    -Location 'Global' `
                                    -Name $alert_name  `
                                    -ResourceGroupName $ResourceGroupName `
                                    -Scope $scope `
                                    -Action (New-Object Microsoft.Azure.Management.Monitor.Models.ActivityLogAlertActionGroup $actiongroup.Id) `
                                    -Condition $condition1, $condition2, $condition3 | Out-Null

                                Write-Host "configured successfully" -ForegroundColor Green
                            }

                            # Monitor DB Audit Changes
                            $alert_name = "$ServerName-DB-$DB-Audit"

                            Write-Host "[Azure Database Config]" -NoNewline -ForegroundColor Yellow
                            Write-Host "Alert: $alert_name " -NoNewline

                            $alert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -eq $alert_name }
                            If ($alert) {
                                Write-Host "already exists" -ForegroundColor Green
                            }
                            Else {
                                $scope = "/subscriptions/$SubId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName/databases/$DB/auditingSettings/default"
                                $condition1 = New-AzActivityLogAlertCondition -Field 'category' -Equal 'Administrative'
                                $condition2 = New-AzActivityLogAlertCondition -Field 'level' -Equal 'Informational'
                                $condition3 = New-AzActivityLogAlertCondition -Field 'status' -Equal 'Succeeded'

                                Set-AzActivityLogAlert `
                                    -Location 'Global' `
                                    -Name $alert_name  `
                                    -ResourceGroupName $ResourceGroupName `
                                    -Scope $scope `
                                    -Action (New-Object Microsoft.Azure.Management.Monitor.Models.ActivityLogAlertActionGroup $actiongroup.Id) `
                                    -Condition $condition1, $condition2, $condition3 | Out-Null

                                Write-Host "configured successfully" -ForegroundColor Green
                            }
                        }
                        Else {
                            Write-Host "KO - Action Group not Found" -ForegroundColor Red
                        }
                    }
                }
            }
            Catch{
                Write-Host "KO" -ForegroundColor Red
                Write-Host $PSItem.Exception.InnerException -ForegroundColor Red
            }
        }
    }
}

################################################################## Azure Automation Schedule ##################################################################

Login-AzAccount
Clear

# Global param
$subscription = 'Visual Studio Ultimate avec MSDN'
Select-AzSubscription -Subscription $subscription | Out-Null
$SqlServer = 'azsqldbp-bi'
$Database = 'Powersaturday'

$subscriptionOMS = 'Visual Studio Ultimate avec MSDN'
$ResourceGroupNameOMS = 'core-rg'
$WS = 'azomsp-core'
$subscriptionSQL = 'Visual Studio Ultimate avec MSDN'
$ResourceGroupNameSQL = 'az-p-bi-database-rg'
$SqlServerName = 'azsqldbp-bi'
$ADSRecipientsEmails = 'mikedavem1@hotmail.com'
$AlertActionGroupResourceGroupName = 'Default-ActivityLogAlerts'
$AlertActionGroupName = 'Send_Email_To_Azure_Admins'
$ADSGroupResourceGroupName = 'az-p-bi-database-rg'
$ADSStorageaccountName = 'azstoreadspbi'

Select-AzSubscription -Subscription $subscriptionOMS | Out-Null
$oms = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupNameOMS -Name $WS

Select-AzSubscription -Subscription $subscriptionSQL | Out-Null

Set-AzServerConfig `
    -SubId $subscription `
    -ResourceGroupName $ResourceGroupNameSQL `
    -ServerName $SqlServerName `
    -omsId $oms.ResourceId `
    -ADSRecipientsEmails $ADSRecipientsEmails `
    -AlertActionGroupName $AlertActionGroupName `
    -AlertActionGroupResourceGroupName $AlertActionGroupResourceGroupName `
    -ADSGroupResourceGroupName $ADSGroupResourceGroupName `
    -ADSStorageaccountName $ADSStorageaccountName `
    -SkipTDE -SkipAudit -SkipAutomaticTuning -SkipAlerts

    
################################################################## Azure SQL DBs Config ##################################################################
$CriticalDBs = @()
$DatabaseName = @('Powersaturday')

$DatabaseName | Set-AzDatabaseConfig `
    -SubName $subscriptionSQL `
    -ResourceGroupName $ResourceGroupNameSQL `
    -ServerName $SqlServerName `
    -CriticalDBs $CriticalDBs `
    -AlertActionGroupResourceGroupName $AlertActionGroupResourceGroupName `
    -AlertActionGroupName $AlertActionGroupName 







