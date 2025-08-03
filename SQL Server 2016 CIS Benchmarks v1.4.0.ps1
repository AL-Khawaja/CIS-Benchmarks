#Created by: Uncle Khawaja Mohammad
#Date: 2025-7-22
#CIS Benchmarks for SQL Server 2016 Version: 1.4.0



# PowerShell script to audit SQL Server 2016 against CIS Benchmarks v1.4.0 (Automated checks only)
# Requires SQL Server Management Objects (SMO) and PowerShell SQL Server module
# Run with sysadmin privileges on the SQL Server instance
# Manual Changes for automates: 2.12 & 5.1
# Import required modules
Import-Module SqlServer -ErrorAction SilentlyContinue

# Configuration
$serverInstance = "KHAWAJA"  # Replace with your SQL Server instance name
$outputCsv = ".\ComplianceScore.csv"  # Output file
$results = @()
$totalChecks = 36
$passCount = 0
$failCount = 0

# Function to execute SQL query and return dataset
function Invoke-SqlQuery {
    param ($Query)
    try {
        $dataset = Invoke-Sqlcmd -ServerInstance $serverInstance -Query $Query -ErrorAction Stop
        return $dataset
    } catch {
        Write-Host "Error executing query: $Query" -ForegroundColor Red
        return $null
    }
}

# Function to add result to output and update counters
function Add-Result {
    param ($CheckId, $Description, $Status, $CurrentValue, $ExpectedValue)
    $script:results += [PSCustomObject]@{
        CheckId       = $CheckId
        Description   = $Description
        Status        = $Status
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
    }
    if ($Status -eq "Pass") {
        $script:passCount++
    } else {
        $script:failCount++
    }
}

# CIS Check 2.1: Ensure 'Ad Hoc Distributed Queries' is set to '0'
$query = "SELECT name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
$dataset = Invoke-SqlQuery -Query $query
if ($dataset) {
    $value = $dataset.value_in_use
    $status = if ($value -eq 0) { "Pass" } else { "Fail" }
    Add-Result -CheckId "2.1" -Description "Ensure 'Ad Hoc Distributed Queries' is set to '0'" `
               -Status $status -CurrentValue $value -ExpectedValue 0
} else {
    Add-Result -CheckId "2.1" -Description "Ensure 'Ad Hoc Distributed Queries' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue 0
}

# CIS Check 2.2: Ensure CLR is disabled or strict security is enabled
$checkId = "2.2"
$description = "Ensure CLR is disabled or strict CLR security is enabled"

# Check 'clr strict security'
$strictSecurity = Invoke-SqlQuery -Query "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name = 'clr strict security';"

if ($strictSecurity -and $strictSecurity.value_configured -eq 1 -and $strictSecurity.value_in_use -eq 1) {
    Add-Result -CheckId $checkId -Description "$description (strict security enabled, check not applicable)" `
               -Status "Pass" -CurrentValue "clr strict security = 1" -ExpectedValue "Not Applicable (strict security = 1)"
} else {
    # Check 'clr enabled'
    $clr = Invoke-SqlQuery -Query "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name = 'clr enabled';"
    if ($clr -and $clr.value_configured -eq 0 -and $clr.value_in_use -eq 0) {
        Add-Result -CheckId $checkId -Description $description -Status "Pass" `
                   -CurrentValue "clr enabled = 0" -ExpectedValue 0
    } elseif ($clr) {
        $val = "Configured: $($clr.value_configured), InUse: $($clr.value_in_use)"
        Add-Result -CheckId $checkId -Description $description -Status "Fail" `
                   -CurrentValue $val -ExpectedValue 0
    } else {
        Add-Result -CheckId $checkId -Description $description -Status "Error" `
                   -CurrentValue "Failed to query 'clr enabled'" -ExpectedValue 0
    }
}

# CIS Check 2.3: Ensure 'Cross DB Ownership Chaining' is set to '0'
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'cross db ownership chaining';"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.3" -Description "Ensure 'Cross DB Ownership Chaining' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.3" -Description "Ensure 'Cross DB Ownership Chaining' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}


# CIS Check 2.4: Ensure 'Database Mail XPs' is set to '0'
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'Database Mail XPs';"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.4" -Description "Ensure 'Database Mail XPs' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.4" -Description "Ensure 'Database Mail XPs' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}

# CIS Check 2.5: Ensure 'Ole Automation Procedures' is set to '0'
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.5" -Description "Ensure 'Ole Automation Procedures' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.5" -Description "Ensure 'Ole Automation Procedures' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}

# CIS Check 2.6: Ensure 'Remote Access' is set to '0'
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'remote access';"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.6" -Description "Ensure 'Remote Access' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.6" -Description "Ensure 'Remote Access' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}

# CIS Check 2.7: Ensure 'Remote Admin Connections' is set to '0' (non-clustered only)
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset -and $dataset.Count -eq 0) {
    # Instance is clustered — check not applicable
    Add-Result -CheckId "2.7" -Description "Ensure 'Remote Admin Connections' is set to '0' (clustered instance)" `
               -Status "Pass" -CurrentValue "Clustered instance - not applicable" -ExpectedValue "Not Applicable"
}
elseif ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.7" -Description "Ensure 'Remote Admin Connections' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.7" -Description "Ensure 'Remote Admin Connections' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}


# CIS Check 2.8: Ensure 'Scan For Startup Procs' is set to '0'
$query = "SELECT CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use
          FROM sys.configurations WHERE name = 'scan for startup procs';"
$dataset = Invoke-SqlQuery -Query $query

if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.8" -Description "Ensure 'Scan For Startup Procs' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.8" -Description "Ensure 'Scan For Startup Procs' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}


# CIS Check 2.9: Ensure 'Trustworthy' Database Property is set to 'Off'
$query = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No databases with Trustworthy ON (excluding msdb)" } else { ($dataset.name -join ", ") }
Add-Result -CheckId "2.9" -Description "Ensure 'Trustworthy' Database Property is set to 'Off' (excluding msdb)" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No databases with Trustworthy ON (excluding msdb)"



# CIS Check 2.11: Ensure SQL Server is configured to use non-default ports
$query = @"
IF (select value_data from sys.dm_server_registry where value_name =
'ListenOnAllIPs') = 1
SELECT count(*) AS port_count FROM sys.dm_server_registry WHERE registry_key like '%IPAll%'
and value_name like '%Tcp%' and value_data='1433' 
ELSE
SELECT count(*) AS port_count FROM sys.dm_server_registry WHERE value_name like '%Tcp%' and
value_data='1433';
"@
$dataset = Invoke-SqlQuery -Query $query
if ($dataset -and $dataset.port_count -ge 0) {
    $portCount = $dataset.port_count
    $status = if ($portCount -eq 0) { "Pass" } else { "Fail" }
    $description = "Ensure SQL Server is configured to use non-default ports"
    if ($portCount -gt 0) { $description += ". Found $portCount TCP configuration(s) using default port 1433" }
    Add-Result -CheckId "2.11" -Description $description -Status $status -CurrentValue $portCount -ExpectedValue 0
} else {
    Add-Result -CheckId "2.11" -Description "Ensure SQL Server is configured to use non-default ports" `
               -Status "Error" -CurrentValue "Unable to retrieve port configuration" -ExpectedValue 0
}

# CIS Check 2.12: Ensure 'Hide Instance' is set to 'Enabled'
$query = @"
DECLARE @getValue INT;
EXEC master.sys.xp_instance_regread
    @rootkey = N'HKEY_LOCAL_MACHINE',
    @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    @value_name = N'HideInstance',
    @value = @getValue OUTPUT;
SELECT @getValue AS hide_instance;
"@
$dataset = Invoke-SqlQuery -Query $query
if ($dataset -and $dataset.hide_instance -in 0, 1) {
    $hideInstanceValue = $dataset.hide_instance
    $status = if ($hideInstanceValue -eq 1) { "Pass" } else { "Fail" }
    $description = "Ensure 'Hide Instance' is set to 'Enabled'"
    if ($hideInstanceValue -eq 0) { $description += ". Instance is not hidden" }
    Add-Result -CheckId "2.12" -Description $description -Status $status -CurrentValue $hideInstanceValue -ExpectedValue 1
} else {
    Add-Result -CheckId "2.12" -Description "Ensure 'Hide Instance' is set to 'Enabled'" `
               -Status "Error" -CurrentValue "Unable to retrieve HideInstance setting" -ExpectedValue 1
}


# CIS Check 2.13: Ensure the 'sa' Login Account is set to 'Disabled'
$query = "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } elseif ($dataset.is_disabled -eq 1) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "1" } else { $dataset.is_disabled }
Add-Result -CheckId "2.13" -Description "Ensure the 'sa' Login Account is set to 'Disabled'" `
           -Status $status -CurrentValue $currentValue -ExpectedValue 1

# CIS Check 2.14: Ensure the 'sa' Login Account has been renamed
$query = "SELECT name FROM sys.server_principals WHERE name = 'sa';"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "'sa' Login Account has been renamed" } else { "'sa' Login Account hasn't been renamed" }
Add-Result -CheckId "2.14" -Description "Ensure the 'sa' Login Account has been renamed" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "'sa' Login Account has been renamed"

# CIS Check 2.15: Ensure 'xp_cmdshell' Server Configuration Option is set to '0' 
$query = "SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
$dataset = Invoke-SqlQuery -Query $query
if ($dataset) {
    $valConf = $dataset.value_configured
    $valUse  = $dataset.value_in_use
    $status = if ($valConf -eq 0 -and $valUse -eq 0) { "Pass" } else { "Fail" }
    $current = "Configured: $valConf, InUse: $valUse"
    Add-Result -CheckId "2.15" -Description "Ensure 'Ole Automation Procedures' is set to '0'" `
               -Status $status -CurrentValue $current -ExpectedValue "Configured: 0, InUse: 0"
} else {
    Add-Result -CheckId "2.5" -Description "Ensure 'Ole Automation Procedures' is set to '0'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue "Configured: 0, InUse: 0"
}


# CIS Check 2.16: Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases
$query = "SELECT name, is_auto_close_on FROM sys.databases WHERE containment <> 0 AND is_auto_close_on = 1;"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No contained databases with AUTO_CLOSE ON" } else { ($dataset.name -join ", ") }
Add-Result -CheckId "2.16" -Description "Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No contained databases with AUTO_CLOSE ON"


# CIS Check 2.17: Ensure no login exists with the name 'sa'
$query = "SELECT name FROM sys.server_principals WHERE name = 'sa';"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No 'sa' login found" } else { "sa login exists" }
Add-Result -CheckId "2.17" -Description "Ensure no login exists with the name 'sa'" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No 'sa' login"

# CIS Check 3.1: Ensure 'Server Authentication' is set to 'Windows Authentication Mode'
$query = "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS auth_mode;"
$dataset = Invoke-SqlQuery -Query $query
if ($dataset) {
    $authMode = $dataset.auth_mode
    $status = if ($authMode -eq 1) { "Pass" } else { "Fail" }
    Add-Result -CheckId "3.1" -Description "Ensure 'Server Authentication' is set to 'Windows Authentication Mode'" `
               -Status $status -CurrentValue $authMode -ExpectedValue 1
} else {
    Add-Result -CheckId "3.1" -Description "Ensure 'Server Authentication' is set to 'Windows Authentication Mode'" `
               -Status "Error" -CurrentValue "Query failed" -ExpectedValue 1
}

# CIS Check 3.2: Ensure 'CONNECT' permissions are revoked from the 'guest' user
$dbQuery = "SELECT name FROM sys.databases WHERE state = 0 AND name NOT IN ('master', 'tempdb', 'msdb');"
$databases = Invoke-SqlQuery -Query $dbQuery
$unauthorizedDbCount = 0
$failedDatabases = @()
$isRDS = (Invoke-SqlQuery -Query "SELECT COUNT(*) AS rds_count FROM sys.databases WHERE name = 'rdsadmin';").rds_count -gt 0
if ($databases) {
    foreach ($db in $databases) {
        $databaseName = $db.name
        if ($isRDS -and $databaseName -eq 'rdsadmin') { continue }
        $query = "USE [$databaseName]; SELECT DB_NAME() AS DatabaseName FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('guest') AND state_desc LIKE 'GRANT%' AND permission_name = 'CONNECT';"
        $dataset = Invoke-SqlQuery -Query $query
        if ($dataset -and $dataset.DatabaseName) {
            $unauthorizedDbCount++
            $failedDatabases += $databaseName
        }
    }
    $status = if ($unauthorizedDbCount -eq 0) { "Pass" } else { "Fail" }
    $description = "Ensure 'CONNECT' permissions are revoked from the 'guest' user in all databases except master, tempdb, msdb" + $(if ($isRDS) { ", and rdsadmin (AWS RDS)" })
    if ($failedDatabases.Count -gt 0) { $description += ". Found unauthorized CONNECT permissions in: " + ($failedDatabases -join ", ") }
    Add-Result -CheckId "3.2" -Description $description -Status $status -CurrentValue $unauthorizedDbCount -ExpectedValue 0
} else {
    Add-Result -CheckId "3.2" -Description "Ensure 'CONNECT' permissions are revoked from the 'guest' user in all databases except master, tempdb, msdb" `
               -Status "Error" -CurrentValue "No databases found" -ExpectedValue 0
}


# CIS Check 3.3: Ensure no orphaned users exist in any database
$dbQuery = "SELECT name FROM sys.databases WHERE state = 0;"
$databases = Invoke-SqlQuery -Query $dbQuery
$orphanedDbCount = 0
$failedDatabases = @()
if ($databases) {
    foreach ($db in $databases) {
        $databaseName = $db.name
        $query = "USE [$databaseName]; SELECT dp.name AS orphan_user_name FROM sys.database_principals AS dp LEFT JOIN sys.server_principals AS sp ON dp.sid = sp.sid WHERE sp.sid IS NULL AND dp.authentication_type_desc = 'INSTANCE';"
        $dataset = Invoke-SqlQuery -Query $query
        if ($dataset -and $dataset.orphan_user_name) {
            $orphanedDbCount++
            $failedDatabases += $databaseName
        }
    }
    $status = if ($orphanedDbCount -eq 0) { "Pass" } else { "Fail" }
    $description = "Ensure no orphaned users exist in any database"
    if ($failedDatabases.Count -gt 0) { $description += ". Found orphaned users in: " + ($failedDatabases -join ", ") }
    Add-Result -CheckId "3.3" -Description $description -Status $status -CurrentValue $orphanedDbCount -ExpectedValue 0
} else {
    Add-Result -CheckId "3.3" -Description "Ensure no orphaned users exist in any database" `
               -Status "Error" -CurrentValue "No databases found" -ExpectedValue 0
}


# CIS Check 3.4: Ensure SQL Authentication is not used in contained databases
$query = "SELECT name AS DBUser FROM sys.database_principals WHERE name NOT IN ('dbo','Information_Schema','sys','guest') AND type IN ('U','S','G') AND authentication_type = 2;"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No SQL auth in contained databases" } else { ($dataset.DBUser -join ", ") }
Add-Result -CheckId "3.4" -Description "Ensure SQL Authentication is not used in contained databases" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No SQL auth in contained databases"


# CIS Check 3.8: Ensure only default permissions are granted to the public server role
$query = "SELECT * FROM master.sys.server_permissions WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%') AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id IN (2,3,4,5));"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No additional public permissions" } else { ($dataset.permission_name -join ", ") }
Add-Result -CheckId "3.8" -Description "Ensure only default permissions are granted to the public server role" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No additional public permissions"

# CIS Check 3.9: Ensure Windows BUILTIN groups are not SQL Logins
$query = "SELECT pr.[name] FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name LIKE 'BUILTIN%';"
$dataset = Invoke-SqlQuery -Query $query
$status = if ($null -eq $dataset) { "Pass" } else { "Fail" }
$currentValue = if ($null -eq $dataset) { "No BUILTIN group logins" } else { ($dataset.name -join ", ") }
Add-Result -CheckId "3.9" -Description "Ensure Windows BUILTIN groups are not SQL Logins" `
           -Status $status -CurrentValue $currentValue -ExpectedValue "No BUILTIN group logins"

# CIS Check 3.10: Ensure Windows local groups are not SQL Logins
$query = "USE [master]; SELECT pr.[name] AS LocalGroupName FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.[principal_id] = pe.[grantee_principal_id] WHERE pr.[type_desc] = 'WINDOWS_GROUP' AND pr.[name] LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';"
$dataset = Invoke-SqlQuery -Query $query
$groupCount = if ($dataset) { @($dataset | Select-Object -Property LocalGroupName -Unique).Count } else { 0 }
$status = if ($groupCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure Windows local groups are not SQL Logins"
if ($groupCount -gt 0) { $description += ". Found Windows local groups as SQL Logins: " + (($dataset.LocalGroupName | Select-Object -Unique) -join ", ") }
Add-Result -CheckId "3.10" -Description $description -Status $status -CurrentValue $groupCount -ExpectedValue 0

# CIS Check 3.11: Ensure the public role in msdb is not granted access to SQL Agent proxies
$query = "USE [msdb]; SELECT sp.name AS proxyname FROM dbo.sysproxylogin spl JOIN sys.database_principals dp ON dp.sid = spl.sid JOIN sysproxies sp ON sp.proxy_id = spl.proxy_id WHERE principal_id = USER_ID('public');"
$dataset = Invoke-SqlQuery -Query $query
$proxyCount = if ($dataset) { @($dataset | Select-Object -Property proxyname -Unique).Count } else { 0 }
$status = if ($proxyCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure the public role in the msdb database is not granted access to SQL Agent proxies"
if ($proxyCount -gt 0) { $description += ". Found proxies accessible to public: " + (($dataset.proxyname | Select-Object -Unique) -join ", ") }
Add-Result -CheckId "3.11" -Description $description -Status $status -CurrentValue $proxyCount -ExpectedValue 0

# CIS Check 4.2: Ensure SQL logins with sysadmin or CONTROL SERVER permissions have password expiration checked
$query = "SELECT l.[name], 'sysadmin membership' AS 'Access_Method' FROM sys.sql_logins AS l WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND l.is_expiration_checked <> 1 UNION ALL SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method' FROM sys.sql_logins AS l JOIN sys.server_permissions AS p ON l.principal_id = p.grantee_principal_id WHERE p.type = 'CL' AND p.state IN ('G', 'W') AND l.is_expiration_checked <> 1;"
$dataset = Invoke-SqlQuery -Query $query
$unauthorizedLoginCount = 0
$failedLogins = @()
$isRDS = (Invoke-SqlQuery -Query "SELECT COUNT(*) AS rds_count FROM sys.databases WHERE name = 'rdsadmin';").rds_count -gt 0
if ($dataset -and $dataset.name) {
    $logins = @($dataset | Select-Object -Property name -Unique)
    foreach ($login in $logins) {
        if (-not ($isRDS -and $login.name -eq 'rdsa')) {
            $unauthorizedLoginCount++
            $failedLogins += $login.name
        }
    }
}
$status = if ($unauthorizedLoginCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure SQL logins with sysadmin or CONTROL SERVER permissions have password expiration checked"
if ($failedLogins.Count -gt 0) { $description += ". Found logins without password expiration: " + ($failedLogins -join ", ") }
Add-Result -CheckId "4.2" -Description $description -Status $status -CurrentValue $unauthorizedLoginCount -ExpectedValue 0

# CIS Check 4.3: Ensure SQL logins have password complexity enforced
$query = "SELECT name, is_disabled FROM sys.sql_logins WHERE is_policy_checked = 0;"
$dataset = Invoke-SqlQuery -Query $query
$failedLogins = @()
if ($dataset) {
    foreach ($login in $dataset) {
        if ($login.is_disabled -eq 0) {
            $failedLogins += $login.name
        }
    }
}
$status = if ($failedLogins.Count -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure SQL logins have password complexity enforced"
if ($failedLogins.Count -gt 0) {
    $description += ". Found enabled logins without password complexity: " + ($failedLogins -join ", ")
}
Add-Result -CheckId "4.3" -Description $description -Status $status -CurrentValue $failedLogins.Count -ExpectedValue 0


# CIS Check 5.1: Ensure Number of Error Log Files is Greater Than or Equal to 12 or Set to -1
$query = "DECLARE @NumErrorLogs int; EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'NumErrorLogs', @NumErrorLogs OUTPUT; SELECT ISNULL(@NumErrorLogs, -1) AS NumberOfLogFiles;"
$dataset = Invoke-SqlQuery -Query $query
$logFileCount = if ($dataset -and $null -ne $dataset.NumberOfLogFiles) { $dataset.NumberOfLogFiles } else { -1 }
$status = if ($logFileCount -eq -1 -or $logFileCount -ge 12) { "Pass" } else { "Fail" }
$description = "Ensure Number of Error Log Files is Greater Than or Equal to 12 or Set to -1"
if ($status -eq "Fail") { $description += ". Found $logFileCount error log files configured" }
Add-Result -CheckId "5.1" -Description $description -Status $status -CurrentValue $logFileCount -ExpectedValue "12 or higher, or -1"


# CIS Check 5.2: Ensure 'Default Trace Enabled' Server Configuration Option is Set to '1'
$query = "SELECT name, CAST(value AS int) AS value_configured, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations WHERE name = 'default trace enabled';"
$dataset = Invoke-SqlQuery -Query $query
$isEnabled = if ($dataset) { $dataset.value_configured -eq 1 -and $dataset.value_in_use -eq 1 } else { $false }
$status = if ($isEnabled) { "Pass" } else { "Fail" }
$description = "Ensure 'Default Trace Enabled' Server Configuration Option is Set to '1'"
if (-not $isEnabled -and $dataset) { $description += ". Configured: " + $dataset.value_configured + ", In Use: " + $dataset.value_in_use }
Add-Result -CheckId "5.2" -Description $description -Status $status -CurrentValue $(if ($isEnabled) { "Enabled" } else { "Disabled" }) -ExpectedValue "Enabled"


# CIS Check 5.3: Ensure 'Login Auditing' is set to 'failed logins' or 'all'
$query = "EXEC xp_loginconfig 'audit level';"
$dataset = Invoke-SqlQuery -Query $query
$auditLevel = if ($dataset -and $dataset.config_value) { $dataset.config_value.Trim().ToLower() } else { "Unknown" }
$status = if ($auditLevel -in 'failure', 'all') { "Pass" } else { "Fail" }
$description = "Ensure 'Login Auditing' is set to 'failed logins' or 'all'"
if ($status -eq "Fail") { $description += ". Found audit level: $auditLevel" }
Add-Result -CheckId "5.3" -Description $description -Status $status -CurrentValue $auditLevel -ExpectedValue "failure or all"

# Not applicable for my environment (Space issues)
# CIS Check 5.4: Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' and other required actions
# $query = "SELECT S.name AS Audit_Name, CASE S.is_state_enabled WHEN 1 THEN 'Y' ELSE 'N' END AS Audit_Enabled, SA.name AS Audit_Specification_Name, CASE SA.is_state_enabled WHEN 1 THEN 'Y' ELSE 'N' END AS Audit_Specification_Enabled, SAD.audit_action_name, SAD.audited_result FROM sys.server_audit_specification_details SAD JOIN sys.server_audit_specifications SA ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits S ON SA.audit_guid = S.audit_guid WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD', 'ADDP', 'ADSP', 'OPSV') OR (SAD.audit_action_id IN ('DAGS', 'DAGF') AND (SELECT COUNT(*) FROM sys.databases WHERE containment = 1) > 0);"
# $requiredActions = @("AUDIT_CHANGE_GROUP", "FAILED_LOGIN_GROUP", "SUCCESSFUL_LOGIN_GROUP", "DATABASE_ROLE_MEMBER_CHANGE_GROUP", "SERVER_ROLE_MEMBER_CHANGE_GROUP", "SERVER_OPERATION_GROUP")
# $dataset = Invoke-SqlQuery -Query $query
# $misconfiguredCount = 0
# $missingActions = @()
# $isRDS = (Invoke-SqlQuery -Query "SELECT COUNT(*) AS rds_count FROM sys.databases WHERE name = 'rdsadmin';").rds_count -gt 0
# $hasContainedDbs = (Invoke-SqlQuery -Query "SELECT COUNT(*) AS contained_count FROM sys.databases WHERE containment = 1;").contained_count -gt 0
# if ($hasContainedDbs) { $requiredActions += "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP", "FAILED_DATABASE_AUTHENTICATION_GROUP" }
# if ($dataset -and $dataset.audit_action_name) {
#     $foundActions = @($dataset | Select-Object -Property audit_action_name -Unique | ForEach-Object { $_.audit_action_name })
#     foreach ($action in $requiredActions) { if ($action -notin $foundActions) { $misconfiguredCount++; $missingActions += $action } }
#     foreach ($row in $dataset) { if ($row.Audit_Enabled -ne 'Y' -or $row.Audit_Specification_Enabled -ne 'Y' -or $row.audited_result -notlike '*SUCCESS AND FAILURE*') { $misconfiguredCount++ } }
# } else { $misconfiguredCount = $requiredActions.Count; $missingActions = $requiredActions }
# $status = if ($misconfiguredCount -eq 0) { "Pass" } else { "Fail" }
# $description = "Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' and other required actions"
# Add-Result -CheckId "5.4" -Description $description -Status $status -CurrentValue $misconfiguredCount -ExpectedValue "0 missing or misconfigured actions"


# CIS Check 6.2: Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS'
$dbQuery = "SELECT name FROM sys.databases WHERE state = 0;"
$databases = Invoke-SqlQuery -Query $dbQuery
$nonSafeAssemblyCount = 0
$failedAssemblies = @()
if ($databases) {
    foreach ($db in $databases) {
        $databaseName = $db.name
        $query = "USE [$databaseName]; SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1 AND name <> 'Microsoft.SqlServer.Types';"
        $dataset = Invoke-SqlQuery -Query $query
        if ($dataset -and $dataset.name) {
            foreach ($row in $dataset) {
                if ($row.permission_set_desc -ne 'SAFE_ACCESS') {
                    $nonSafeAssemblyCount++
                    $failedAssemblies += "${databaseName}:$($row.name) ($($row.permission_set_desc))"
                }
            }
        }
    }
}
$status = if ($nonSafeAssemblyCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for all user-defined CLR assemblies"
if ($failedAssemblies.Count -gt 0) { $description += ". Found assemblies with non-SAFE_ACCESS: " + ($failedAssemblies -join ", ") }
Add-Result -CheckId "6.2" -Description $description -Status $status -CurrentValue $nonSafeAssemblyCount -ExpectedValue 0

# CIS Check 7.1: Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher
$dbQuery = "SELECT name FROM sys.databases WHERE state = 0 AND database_id > 4;"
$databases = Invoke-SqlQuery -Query $dbQuery
$nonAesKeyCount = 0
$failedKeys = @()
if ($databases) {
    foreach ($db in $databases) {
        $databaseName = $db.name
        $query = "USE [$databaseName]; SELECT db_name() AS Database_Name, name AS Key_Name, algorithm_desc FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128', 'AES_192', 'AES_256');"
        $dataset = Invoke-SqlQuery -Query $query
        if ($dataset -and $dataset.Key_Name) {
            foreach ($row in $dataset) {
                $nonAesKeyCount++
                $failedKeys += "$($row.Database_Name):$($row.Key_Name) ($($row.algorithm_desc))"
            }
        }
    }
}
$status = if ($nonAesKeyCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases"
if ($failedKeys.Count -gt 0) { $description += ". Found keys with non-AES algorithms: " + ($failedKeys -join ", ") }
Add-Result -CheckId "7.1" -Description $description -Status $status -CurrentValue $nonAesKeyCount -ExpectedValue 0

# CIS Check 7.2: Ensure 'Asymmetric Key Size' is set to 'greater than or equal to 2048'
$dbQuery = "SELECT name FROM sys.databases WHERE state = 0 AND database_id > 4;"
$databases = Invoke-SqlQuery -Query $dbQuery
$weakKeyCount = 0
$failedKeys = @()
if ($databases) {
    foreach ($db in $databases) {
        $databaseName = $db.name
        $query = "USE [$databaseName]; SELECT db_name() AS Database_Name, name AS Key_Name, key_length FROM sys.asymmetric_keys WHERE key_length < 2048;"
        $dataset = Invoke-SqlQuery -Query $query
        if ($dataset -and $dataset.Key_Name) {
            foreach ($row in $dataset) {
                $weakKeyCount++
                $failedKeys += "$($row.Database_Name):$($row.Key_Name) (Key Length: $($row.key_length))"
            }
        }
    }
}
$status = if ($weakKeyCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure 'Asymmetric Key Size' is set to 'greater than or equal to 2048' in non-system databases"
if ($failedKeys.Count -gt 0) { $description += ". Found keys with key length < 2048: " + ($failedKeys -join ", ") }
Add-Result -CheckId "7.2" -Description $description -Status $status -CurrentValue $weakKeyCount -ExpectedValue 0

# CIS Check 7.3: Ensure Database Backups are Encrypted
$query = "SELECT b.key_algorithm, b.encryptor_type, d.is_encrypted, b.database_name FROM msdb.dbo.backupset b INNER JOIN sys.databases d ON b.database_name = d.name WHERE b.key_algorithm IS NULL AND b.encryptor_type IS NULL AND d.is_encrypted = 0;"
$dataset = Invoke-SqlQuery -Query $query
$nonEncryptedBackupCount = if ($dataset) { @($dataset | Select-Object -Property database_name -Unique).Count } else { 0 }
$status = if ($nonEncryptedBackupCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure Database Backups are Encrypted"
if ($nonEncryptedBackupCount -gt 0) { $description += ". Found non-encrypted backups for databases: " + (($dataset.database_name | Select-Object -Unique) -join ", ") }
Add-Result -CheckId "7.3" -Description $description -Status $status -CurrentValue $nonEncryptedBackupCount -ExpectedValue 0

# CIS Check 7.4: Ensure Network Encryption is Configured and Enabled
$query = "USE [master]; SELECT DISTINCT encrypt_option FROM sys.dm_exec_connections;"
$dataset = Invoke-SqlQuery -Query $query
$nonEncryptedConnections = if ($dataset -and ($dataset.encrypt_option | Select-Object -Unique) -contains "FALSE") { 1 } else { 0 }
$status = if ($nonEncryptedConnections -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure Network Encryption is Configured and Enabled"
if ($nonEncryptedConnections -gt 0) { $description += ". Non-encrypted connections detected" }
Add-Result -CheckId "7.4" -Description $description -Status $status -CurrentValue $nonEncryptedConnections -ExpectedValue 0

# CIS Check 7.5: Ensure Databases are Encrypted with TDE
$query = "SELECT database_id, name, is_encrypted FROM sys.databases WHERE database_id > 4 AND is_encrypted != 1;"
$dataset = Invoke-SqlQuery -Query $query
$nonEncryptedDbCount = if ($dataset) { @($dataset | Select-Object -Property name -Unique).Count } else { 0 }
$status = if ($nonEncryptedDbCount -eq 0) { "Pass" } else { "Fail" }
$description = "Ensure user databases are encrypted with Transparent Data Encryption (TDE)"
if ($nonEncryptedDbCount -gt 0) { $description += ". Found non-encrypted databases: " + (($dataset.name | Select-Object -Unique) -join ", ") }
Add-Result -CheckId "7.5" -Description $description -Status $status -CurrentValue $nonEncryptedDbCount -ExpectedValue 0


# Calculate score and output results
$scorePercentage = [math]::Round(($passCount / $totalChecks) * 100, 2)
Write-Host "Passed: $passCount, Failed: $failCount, Total: $totalChecks ($scorePercentage% compliance)" -ForegroundColor Green
$results | Export-Csv -Path $outputCsv -NoTypeInformation
Write-Host "Audit completed. Results saved to $outputCsv" -ForegroundColor Green
$results | Format-Table -AutoSize