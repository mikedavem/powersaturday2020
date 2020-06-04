param(
        [parameter(Mandatory=$True)]
        [string] $SqlInstance
        ,
        [parameter(Mandatory=$True)]
        [string] $Database
        ,
        [parameter(Mandatory=$False)]
        [int] $IdxOptRgsThreshold = 80
        ,
        [parameter(Mandatory=$False)]
        [int] $IdxRebuildThreshold = 10
        ,
        [parameter(Mandatory=$False)]
        [int] $StatisticsAgingThreshold = 7
        ,
        [parameter(Mandatory=$False)]
        [String]$EnvTarget="ACC"
        ,
        [parameter(Mandatory=$False)]
        [ValidateSet('idx_maintenance','stats_maintenance','idx_usage_stats','all')]
        [String]$Action
)

# Choose the corresponding keyvault
switch ($EnvTarget) {
    "PROD" { $KeyvaultName = "azkv01p"}
}

Try {
    # Run runbook as special account
    $AzureAutomationConnectionName = "AzureRunAsConnection"
    $ServicePrincipalConnection = Get-AutomationConnection -Name $AzureAutomationConnectionName

    # Connect to get access to Key Vault
    Connect-AzAccount `
        -ServicePrincipal `
        -ApplicationId $ServicePrincipalConnection.ApplicationId `
        -Tenant $ServicePrincipalConnection.TenantId `
        -CertificateThumbprint $ServicePrincipalConnection.CertificateThumbprint | Out-Null

    # Get info for connection through PowerShell registred app which has access to the SQL Azure Dbs
    $tenantName = $ServicePrincipalConnection.TenantId
    $clientId = (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQLSPwshAppId").SecretValueText
    $clientSecret =  ConvertTo-SecureString (Get-AzKeyVaultSecret -VaultName $KeyvaultName -Name "AZSQLSPwshAppSecret").SecretValueText -AsPlainText -Force
    $resourceUri = "https://database.windows.net/"
    $authorityUri = "https://login.microsoftonline.com/$tenantName"
    [String]$debugMsg = ''
    $response = Get-ADALToken -ClientId $clientId -ClientSecret $clientSecret -Resource $resourceUri -Authority $authorityUri -TenantId $tenantName

    # Connection String
    $connectionString = "Server=tcp:$SqlInstance,1433;Initial Catalog=$Database;Persist Security Info=False;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;"

    # Create the connection object
    $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)

    # Set AAD generated token to SQL connection token
    $connection.AccessToken = $response.AccessToken

    # Performs the requested action(s)
    If ($action -eq 'idx_maintenance' -or $action -eq 'all'){
    $debugMsg = 'idx_maintenance,'
$query = @"
EXEC [maintenance].[dbi_maintenance_user_indexes_databases]
    @dbs_to_maintain = '$Database',
    @debug = 0,
    @hp_to_rebuild = -1,
    @idx_to_rebuild = -1,
    @p_idx_cci_opt_rgs_threshold = $IdxOptRgsThreshold,
    @p_idx_cci_rebuild_threshold = $IdxRebuildThreshold;
"@
    }

    If ($action -eq 'stats_maintenance' -or $action -eq 'all'){
    $debugMsg += 'stats_maintenance,'
$query += @"
    `n`n
EXECUTE [maintenance].[dbi_maintenance_user_statistics_databases]
    @dbs_to_maintain = '$Database',
    @debug = 0,
    @p_statistics_aging_threshold = $StatisticsAgingThreshold,
    @p_statistics_scan_method = 'FULLSCAN'
"@
    }

    If ($action -eq 'idx_usage_stats' -or $action -eq 'all'){
    $debugMsg += 'idx_usage_stats'
$query += @"
`n`n
SET NOCOUNT ON
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

DECLARE @max BIGINT = COALESCE((SELECT MAX(capture_id) FROM maintenance.ls_index_usage_stats), 0);

DECLARE  @schema_name sysname = 'dbo'
, @table_or_view_name sysname = NULL --= 'maTable' -- si NULL, Ã©tudie tous les index de toutes les table du schÃ©ma
, @index_name sysname = NULL -- si NULL, Ã©tudie tous les index de la table
, @separator varchar(2) = ', '
----------------------------------------------------------------------------------------------------------------------
INSERT INTO [maintenance].[ls_index_usage_stats]
        ([capture_id]
        ,[capture_date]
        ,[schema_table_name]
        ,[index_name]
        ,[row_count]
        ,[nb_partitions]
        ,[type_desc]
        ,[is_primary_key]
        ,[is_unique]
        ,[pages_count]
        ,[index_size_MB]
        ,[last_stat_update]
        ,[user_seeks]
        ,[user_scans]
        ,[user_lookups]
        ,[total_user_searches]
        ,[last_user_seek]
        ,[last_user_scan]
        ,[last_user_lookup])
SELECT DISTINCT
    @max + 1 AS capture_id,
    GETDATE() AS capture_date
    , S.name + '.' + O.name AS schema_table_name
    , I.name AS index_name
    , PS.row_count
    , PS.nb_partitions
    , I.type_desc
    , I.is_primary_key
    , I.is_unique
    , PS.used_page_count AS pages_count
    , PS.used_page_count / 128 AS index_size_MB
    , STATS_DATE(O.object_id, I.index_id) AS last_stat_update
    , IUS.user_seeks
    , IUS.user_scans
    , IUS.user_lookups
    , (IUS.user_seeks + IUS.user_scans + IUS.user_lookups) AS total_user_searches
    , IUS.last_user_seek
    , IUS.last_user_scan
    , IUS.last_user_lookup
FROM    sys.schemas AS S
INNER JOIN  sys.objects AS O
    ON S.schema_id = O.schema_id
INNER JOIN  sys.indexes AS I
    ON O.object_id = I.object_id
INNER JOIN  sys.index_columns AS IC
    ON IC.object_id = I.object_id
    AND IC.index_id = I.index_id
LEFT JOIN  sys.dm_db_index_usage_stats AS IUS
    ON IUS.object_id = I.object_id
    AND IUS.index_id = I.index_id
    AND IUS.database_id = DB_ID()
INNER JOIN  (
    SELECT
        PS1.object_id,
        PS1.index_id,
        COUNT(*) AS nb_partitions,
        SUM(PS1.row_count) AS row_count,
        SUM(PS1.used_page_count) AS used_page_count
    FROM
        sys.dm_db_partition_stats AS PS1
    GROUP BY
        PS1.object_id, PS1.index_id
) AS PS
ON PS.object_id = I.object_id
AND PS.index_id = I.index_id
WHERE    (@schema_name IS NULL OR S.name = @schema_name)
AND    (@table_or_view_name IS NULL OR O.name = @table_or_view_name)
AND    (@index_name IS NULL OR I.name = @index_name)
ORDER BY  schema_table_name
"@
    }

    # Opens connection to Azure SQL Database and executes a query
    # With Serverless if DB is in auto-pause we need to retry the connection a second time
    $logonAttempt = 0
    $connectionResult = $False

    Write-Output "$(Get-Date): Trying to $SqlInstance instance and $Database database ..."

    while(!($connectionResult) -And ($logonAttempt -le 3)) {
        $LogonAttempt++

        Try {
            # First attempt
            $connection.Open()
            $connectionResult = $True
        }
        Catch {
            $connectionResult = $False
            Start-Sleep -Seconds 20
        }
    }

    If ($logonAttempt -gt 3){
        Throw "$(Get-Date): Error connecting to the $SqlInstance instance and $Database database after more $logonAttempt attempts ..."
    }
    Else {
        # After this, the token is no longer there, I believe this is because the authentication went through already, so it gets rid of it.
        #$connection
        Write-Output "$(Get-Date): Executing $debugMsg task(s) against $SqlInstance instance and $Database database ..."

        $command = New-Object -Type System.Data.SqlClient.SqlCommand($query, $connection)
        $command.CommandTimeout = 0
        $command.ExecuteNonQuery()

        $connection.Close()

        Write-Output "$(Get-Date): Maintenance tasks $debugMsg have been performed on $SqlInstance instance and $Database database ..."

        [String]$Subject = "AzSql-MaintenanceDB - Env: $EnvTarget - Server: $SqlInstance - DB: $Database OK"
        [String]$Body = "AzSql-MaintenanceDB completed sucessfully for the task(s): $debugMsg"

        Invoke-LSSendEmail `
            -SmtpServer $smtpserver `
            -Port 25 `
            -UseSSL $True `
            -From 'azure.automation@leshop.ch' `
            -To 'DL_SQLAdmins@leshop.ch','DL_ECU_IT_DATA@leshop.ch' `
            -Subject $Subject `
            -Body $Body
    }
}
Catch {
    [String]$Subject = "AzSql-MaintenanceDB - Env: $EnvTarget - Server: $SqlInstance - Task(s): $tasks - DB: $Database KO"
    [String]$Body = $_.Exception.Message

    Write-Output $Subject
    Write-Output $Body
}

