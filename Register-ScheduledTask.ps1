<#
.SYNOPSIS
    Registers a scheduled task that runs PingCastle-Notify.ps1.

.DESCRIPTION
    Creates (or updates) a scheduled task running PingCastle-Notify.ps1 as SYSTEM
    by default. On a member server, SYSTEM authenticates to AD as the computer
    account, which is sufficient for a PingCastle healthcheck.

    Must be run from an elevated PowerShell session.

.EXAMPLE
    .\Register-ScheduledTask.ps1
    Weekly on Monday at 08:00 as SYSTEM, using PingCastle-Notify.ps1 next to this script.

.EXAMPLE
    .\Register-ScheduledTask.ps1 -Daily -At 02:00 -RunNow

.EXAMPLE
    .\Register-ScheduledTask.ps1 -User 'DOMAIN\svc-pingcastle$'
    Run as a gMSA instead of SYSTEM.

.EXAMPLE
    .\Register-ScheduledTask.ps1 -Unregister
#>

[CmdletBinding(DefaultParameterSetName = 'Weekly')]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot "PingCastle-Notify.ps1"),
    [string]$TaskName = "PingCastleNotify",
    [string]$At = "08:00",

    [Parameter(ParameterSetName = 'Weekly')]
    [System.DayOfWeek[]]$DaysOfWeek = @('Monday'),

    [Parameter(ParameterSetName = 'Daily')]
    [switch]$Daily,

    # gMSA (DOMAIN\name$) or built-in account; defaults to SYSTEM
    [string]$User = "S-1-5-18",

    [int]$TimeLimitHours = 2,
    [string]$ScriptArguments = "",
    [switch]$RunNow,

    [Parameter(ParameterSetName = 'Unregister')]
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run from an elevated PowerShell session."
}

if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[+] Scheduled task '$TaskName' removed" -ForegroundColor Green
    } else {
        Write-Host "[-] Scheduled task '$TaskName' not found" -ForegroundColor Yellow
    }
    return
}

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Script not found: $ScriptPath"
}
$ScriptPath = (Resolve-Path $ScriptPath).Path
$workDir = Split-Path $ScriptPath

if (-not (Test-Path (Join-Path $workDir ".env"))) {
    Write-Warning ".env not found in $workDir - run Initial-deploy.ps1 or copy .env.example first"
}

$time = [datetime]::ParseExact($At, "HH:mm", $null)

$powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
if ($ScriptArguments) {
    $arguments += " $ScriptArguments"
}

$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $workDir

if ($Daily) {
    $trigger = New-ScheduledTaskTrigger -Daily -At $time
    $scheduleText = "daily at $At"
} else {
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DaysOfWeek -At $time
    $scheduleText = "weekly on $($DaysOfWeek -join ', ') at $At"
}

if ($User -eq "S-1-5-18" -or $User -match '^(NT AUTHORITY\\)?SYSTEM$') {
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    $userText = "SYSTEM"
} elseif ($User.EndsWith('$')) {
    # gMSA
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Password -RunLevel Highest
    $userText = $User
} else {
    Write-Error "Only SYSTEM or a gMSA (ending with `$) is supported. For a regular service account, create the task in taskschd.msc (see README)."
}

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours $TimeLimitHours) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "PingCastle scan and notification (PingCastle-Notify)" -Force | Out-Null

Write-Host "[+] Scheduled task '$TaskName' registered" -ForegroundColor Green
Write-Host "    Runs as : $userText"
Write-Host "    Schedule: $scheduleText"
Write-Host "    Command : $powershell $arguments"
Write-Host ""
Write-Host "[!] .env contains webhook URLs/tokens: restrict $workDir to SYSTEM and Administrators" -ForegroundColor Yellow

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "[+] Task started. Check 'Last Run Result' in taskschd.msc and scan.log in the reports folder." -ForegroundColor Green
}
