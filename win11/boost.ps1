<#
.SYNOPSIS
    Ultimate Windows 11 Optimization Script v2
    - Interactive Tools (Massgrave, CTT, Raphire)
    - Aggressive Service Debloating
    - Power & Visual Tweaks
    - Swap/Ramdisk Reminders
#>

# --- ADMIN CHECK ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Clear-Host

Write-Host "=== WINDOWS OPTIMIZATION STARTING ===" -ForegroundColor Cyan

# --- 1. INTERACTIVE TOOLS ---
Write-Host "`n[1/4] Launching Tools..." -ForegroundColor Yellow

# Massgrave
Write-Host " -> Massgrave (Select activation -> Exit)" -ForegroundColor Gray
irm https://massgrave.dev/get | iex

# Chris Titus Tech
Write-Host " -> CTT WinUtil (Close window when done)" -ForegroundColor Gray
irm https://christitus.com/win | iex

# Win11Debloat
Write-Host " -> Win11Debloat" -ForegroundColor Gray
irm https://github.com/Raphire/Win11Debloat/raw/master/Win11Debloat.ps1 | iex

# --- 2. SERVICES & BLOAT REMOVAL ---
Write-Host "`n[2/4] Disabling Background Services & Telemetry..." -ForegroundColor Yellow

# Services to DISABLE
$services = @(
    "Spooler", "Fax", "TermService", "DiagTrack", "dmwappushservice",
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc",
    "PhoneSvc", "RetailDemo", "StiSvc", "WPDBusEnum", "SCardSvr",
    "lfsvc", "CscService", "SysMain", "WSearch", "WerSvc", "PcaSvc",
    "WalletService", "wisvc", "MapsBroker", "TabletInputService",
    "ClickToRunSvc", "CDPSvc", "SSDPSRV"
)

foreach ($svc in $services) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# VirtualBox Services (Manual)
@("VBoxSDS", "VBoxSVC") | ForEach-Object {
    if (Get-Service $_ -ErrorAction SilentlyContinue) { Set-Service $_ -StartupType Manual }
}

# Block TextInputHost & Telemetry
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TextInputHost.exe"
New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $regPath -Name Debugger -Value "systray.exe" -Force
Stop-Process -Name "TextInputHost" -Force -ErrorAction SilentlyContinue

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
Get-AppxPackage *WebExperience* | Remove-AppxPackage -ErrorAction SilentlyContinue

# Ensure Wi-Fi stays on
Set-Service WlanSvc -StartupType Automatic; Start-Service WlanSvc -ErrorAction SilentlyContinue

# --- 3. POWER & VISUAL TWEAKS ---
Write-Host "`n[3/4] Applying Power & Visual Tweaks..." -ForegroundColor Yellow

# 1. Disable Hibernation (Frees up SSD space equivalent to RAM size)
powercfg -h off

# 2. Set Power Plan to High Performance
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# 3. Disable Mouse Acceleration (Enhance Pointer Precision) for 1:1 movement
# Values: 0 = Off, 1 = On
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -ErrorAction SilentlyContinue

# 4. Disable Transparency Effects (Saves GPU resources)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

# --- 4. CLEANUP & REMINDERS ---
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "             SETUP COMPLETE                  " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "MANUAL ACTIONS REQUIRED:" -ForegroundColor Red
Write-Host "1. DISABLE SWAP (PAGEFILE):" -ForegroundColor Yellow
Write-Host "   (Settings > About > Adv. System Settings > Performance > Advanced > Virtual Memory)" -ForegroundColor Gray
Write-Host "   Only do this if you have 32GB+ RAM." -ForegroundColor DarkGray
Write-Host "2. Tweak Microsoft Edge settings manually." -ForegroundColor White
Write-Host "3. Install 'AIM Toolkit' for Ramdisk usage." -ForegroundColor White
Write-Host "4. Check BIOS: Enable XMP/DOCP for RAM speed." -ForegroundColor White
Write-Host "5. Restart your computer." -ForegroundColor White
Pause
