#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SME Network Security Assessment Framework
    Week 6: Windows Firewall Hardening Script

.DESCRIPTION
    This script implements comprehensive Windows Firewall hardening including:
    - Enabling firewall for all profiles
    - Configuring security zones
    - Setting up strict inbound/outbound rules
    - Blocking known malicious traffic patterns
    - Enabling logging

.PARAMETER Action
    Action to perform: Apply, Test, Backup, Restore, Status, Reset

.PARAMETER BackupPath
    Path for backup/restore operations

.EXAMPLE
    .\firewall_rules.ps1 -Action Apply
    .\firewall_rules.ps1 -Action Backup -BackupPath C:\Backups\firewall.wfw
    .\firewall_rules.ps1 -Action Test

.NOTES
    Author: SME Security Team
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Apply', 'Test', 'Backup', 'Restore', 'Status', 'Reset')]
    [string]$Action = 'Status',

    [Parameter(Mandatory=$false)]
    [string]$BackupPath = "$env:USERPROFILE\Documents\firewall_backup.wfw"
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Config = @{
    # Trusted networks (CIDR notation)
    TrustedNetworks = @(
        "192.168.1.0/24",
        "10.0.0.0/8"
    )

    # Management hosts allowed full access
    ManagementHosts = @(
        "192.168.1.10",
        "192.168.1.11"
    )

    # Allowed inbound services
    AllowedInboundPorts = @(
        @{ Name = "RDP"; Port = 3389; Protocol = "TCP"; ManagementOnly = $true },
        @{ Name = "WinRM"; Port = 5985; Protocol = "TCP"; ManagementOnly = $true },
        @{ Name = "WinRM-HTTPS"; Port = 5986; Protocol = "TCP"; ManagementOnly = $true },
        @{ Name = "HTTP"; Port = 80; Protocol = "TCP"; ManagementOnly = $false },
        @{ Name = "HTTPS"; Port = 443; Protocol = "TCP"; ManagementOnly = $false }
    )

    # Blocked outbound ports (known malicious)
    BlockedOutboundPorts = @(
        @{ Name = "Telnet"; Port = 23; Protocol = "TCP" },
        @{ Name = "TFTP"; Port = 69; Protocol = "UDP" },
        @{ Name = "IRC"; Port = 6667; Protocol = "TCP" },
        @{ Name = "IRC-SSL"; Port = 6697; Protocol = "TCP" },
        @{ Name = "Tor"; Port = 9001; Protocol = "TCP" },
        @{ Name = "Tor-Dir"; Port = 9030; Protocol = "TCP" }
    )

    # Logging settings
    LogPath = "$env:SystemRoot\System32\LogFiles\Firewall"
    LogFileName = "pfirewall.log"
    MaxLogSize = 16384  # KB
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Green }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }

    # Also log to file
    $logFile = Join-Path $Script:Config.LogPath "hardening.log"
    if (!(Test-Path (Split-Path $logFile))) {
        New-Item -ItemType Directory -Path (Split-Path $logFile) -Force | Out-Null
    }
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

function Write-LogInfo { param([string]$Message) Write-Log "INFO" $Message }
function Write-LogWarn { param([string]$Message) Write-Log "WARN" $Message }
function Write-LogError { param([string]$Message) Write-Log "ERROR" $Message }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Backup-FirewallRules {
    param([string]$Path)

    Write-LogInfo "Backing up firewall rules to: $Path"

    try {
        $backupDir = Split-Path $Path
        if (!(Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        # Export firewall policy
        netsh advfirewall export $Path | Out-Null

        if (Test-Path $Path) {
            Write-LogInfo "Backup completed successfully"
            return $true
        } else {
            Write-LogError "Backup file was not created"
            return $false
        }
    }
    catch {
        Write-LogError "Backup failed: $_"
        return $false
    }
}

function Restore-FirewallRules {
    param([string]$Path)

    Write-LogInfo "Restoring firewall rules from: $Path"

    if (!(Test-Path $Path)) {
        Write-LogError "Backup file not found: $Path"
        return $false
    }

    try {
        netsh advfirewall import $Path | Out-Null
        Write-LogInfo "Restore completed successfully"
        return $true
    }
    catch {
        Write-LogError "Restore failed: $_"
        return $false
    }
}

# ============================================================================
# FIREWALL CONFIGURATION FUNCTIONS
# ============================================================================

function Enable-FirewallProfiles {
    Write-LogInfo "Enabling Windows Firewall for all profiles"

    try {
        # Enable firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Set default actions to block
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -NotifyOnListen True `
            -AllowLocalFirewallRules True `
            -AllowLocalIPsecRules True

        Write-LogInfo "Firewall enabled for all profiles"
        return $true
    }
    catch {
        Write-LogError "Failed to enable firewall: $_"
        return $false
    }
}

function Set-FirewallLogging {
    Write-LogInfo "Configuring firewall logging"

    try {
        # Create log directory if needed
        if (!(Test-Path $Script:Config.LogPath)) {
            New-Item -ItemType Directory -Path $Script:Config.LogPath -Force | Out-Null
        }

        $logFile = Join-Path $Script:Config.LogPath $Script:Config.LogFileName

        # Configure logging for all profiles
        foreach ($profile in @('Domain', 'Public', 'Private')) {
            Set-NetFirewallProfile -Profile $profile `
                -LogAllowed True `
                -LogBlocked True `
                -LogIgnored True `
                -LogFileName $logFile `
                -LogMaxSizeKilobytes $Script:Config.MaxLogSize
        }

        Write-LogInfo "Firewall logging configured: $logFile"
        return $true
    }
    catch {
        Write-LogError "Failed to configure logging: $_"
        return $false
    }
}

function Remove-UnnecessaryRules {
    Write-LogInfo "Removing unnecessary default rules"

    try {
        # Disable potentially dangerous built-in rules
        $rulesToDisable = @(
            "File and Printer Sharing*",
            "Network Discovery*",
            "Remote Desktop*",
            "Windows Remote Management*",
            "*mDNS*",
            "*LLMNR*"
        )

        foreach ($pattern in $rulesToDisable) {
            $rules = Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                Write-LogInfo "Disabling rule: $($rule.DisplayName)"
                Disable-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue
            }
        }

        Write-LogInfo "Unnecessary rules disabled"
        return $true
    }
    catch {
        Write-LogError "Failed to remove unnecessary rules: $_"
        return $false
    }
}

function Add-ManagementRules {
    Write-LogInfo "Adding management access rules"

    try {
        # Create rule group for management
        $groupName = "SME Security - Management Access"

        foreach ($host in $Script:Config.ManagementHosts) {
            # RDP access for management hosts
            $rdpRule = @{
                DisplayName = "SME: RDP from $host"
                Description = "Allow RDP from management host"
                Direction = "Inbound"
                Action = "Allow"
                Protocol = "TCP"
                LocalPort = 3389
                RemoteAddress = $host
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @rdpRule -ErrorAction SilentlyContinue | Out-Null

            # WinRM access for management hosts
            $winrmRule = @{
                DisplayName = "SME: WinRM from $host"
                Description = "Allow WinRM from management host"
                Direction = "Inbound"
                Action = "Allow"
                Protocol = "TCP"
                LocalPort = @(5985, 5986)
                RemoteAddress = $host
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @winrmRule -ErrorAction SilentlyContinue | Out-Null

            # SSH access for management hosts
            $sshRule = @{
                DisplayName = "SME: SSH from $host"
                Description = "Allow SSH from management host"
                Direction = "Inbound"
                Action = "Allow"
                Protocol = "TCP"
                LocalPort = 22
                RemoteAddress = $host
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @sshRule -ErrorAction SilentlyContinue | Out-Null

            Write-LogInfo "Added management rules for: $host"
        }

        return $true
    }
    catch {
        Write-LogError "Failed to add management rules: $_"
        return $false
    }
}

function Add-ServiceRules {
    Write-LogInfo "Adding service access rules"

    try {
        $groupName = "SME Security - Services"

        foreach ($service in $Script:Config.AllowedInboundPorts) {
            if ($service.ManagementOnly) {
                # Already handled by management rules
                continue
            }

            $rule = @{
                DisplayName = "SME: $($service.Name) Inbound"
                Description = "Allow $($service.Name) inbound"
                Direction = "Inbound"
                Action = "Allow"
                Protocol = $service.Protocol
                LocalPort = $service.Port
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @rule -ErrorAction SilentlyContinue | Out-Null
            Write-LogInfo "Added rule: $($service.Name) ($($service.Port)/$($service.Protocol))"
        }

        return $true
    }
    catch {
        Write-LogError "Failed to add service rules: $_"
        return $false
    }
}

function Add-BlockRules {
    Write-LogInfo "Adding block rules for known malicious traffic"

    try {
        $groupName = "SME Security - Blocked Traffic"

        # Block outbound to known malicious ports
        foreach ($blocked in $Script:Config.BlockedOutboundPorts) {
            $rule = @{
                DisplayName = "SME: Block $($blocked.Name) Outbound"
                Description = "Block outbound $($blocked.Name)"
                Direction = "Outbound"
                Action = "Block"
                Protocol = $blocked.Protocol
                RemotePort = $blocked.Port
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @rule -ErrorAction SilentlyContinue | Out-Null
            Write-LogInfo "Blocking outbound: $($blocked.Name) ($($blocked.Port)/$($blocked.Protocol))"
        }

        # Block SMB to internet
        $smbInternetRule = @{
            DisplayName = "SME: Block SMB to Internet"
            Description = "Block SMB traffic to non-private addresses"
            Direction = "Outbound"
            Action = "Block"
            Protocol = "TCP"
            RemotePort = @(445, 139)
            RemoteAddress = "Internet"
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @smbInternetRule -ErrorAction SilentlyContinue | Out-Null
        Write-LogInfo "Blocking SMB to Internet"

        # Block NetBIOS to internet
        $netbiosRule = @{
            DisplayName = "SME: Block NetBIOS to Internet"
            Description = "Block NetBIOS traffic to non-private addresses"
            Direction = "Outbound"
            Action = "Block"
            Protocol = "UDP"
            RemotePort = @(137, 138)
            RemoteAddress = "Internet"
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @netbiosRule -ErrorAction SilentlyContinue | Out-Null
        Write-LogInfo "Blocking NetBIOS to Internet"

        return $true
    }
    catch {
        Write-LogError "Failed to add block rules: $_"
        return $false
    }
}

function Add-ICMPRules {
    Write-LogInfo "Configuring ICMP rules"

    try {
        $groupName = "SME Security - ICMP"

        # Allow ping from trusted networks only
        foreach ($network in $Script:Config.TrustedNetworks) {
            $pingRule = @{
                DisplayName = "SME: Allow Ping from $network"
                Description = "Allow ICMP Echo Request from trusted network"
                Direction = "Inbound"
                Action = "Allow"
                Protocol = "ICMPv4"
                IcmpType = 8
                RemoteAddress = $network
                Profile = "Any"
                Group = $groupName
                Enabled = "True"
            }
            New-NetFirewallRule @pingRule -ErrorAction SilentlyContinue | Out-Null
        }

        # Allow outbound ping
        $pingOutRule = @{
            DisplayName = "SME: Allow Ping Outbound"
            Description = "Allow outbound ICMP Echo Request"
            Direction = "Outbound"
            Action = "Allow"
            Protocol = "ICMPv4"
            IcmpType = 8
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @pingOutRule -ErrorAction SilentlyContinue | Out-Null

        Write-LogInfo "ICMP rules configured"
        return $true
    }
    catch {
        Write-LogError "Failed to configure ICMP rules: $_"
        return $false
    }
}

function Add-IPSecRules {
    Write-LogInfo "Configuring IPsec rules"

    try {
        $groupName = "SME Security - IPsec"

        # Allow IKE
        $ikeRule = @{
            DisplayName = "SME: Allow IKE"
            Description = "Allow Internet Key Exchange"
            Direction = "Inbound"
            Action = "Allow"
            Protocol = "UDP"
            LocalPort = 500
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @ikeRule -ErrorAction SilentlyContinue | Out-Null

        # Allow NAT-T
        $nattRule = @{
            DisplayName = "SME: Allow NAT-T"
            Description = "Allow IPsec NAT Traversal"
            Direction = "Inbound"
            Action = "Allow"
            Protocol = "UDP"
            LocalPort = 4500
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @nattRule -ErrorAction SilentlyContinue | Out-Null

        Write-LogInfo "IPsec rules configured"
        return $true
    }
    catch {
        Write-LogError "Failed to configure IPsec rules: $_"
        return $false
    }
}

function Set-StrictOutbound {
    Write-LogInfo "Configuring strict outbound rules"

    try {
        $groupName = "SME Security - Outbound"

        # Allow DNS
        $dnsRule = @{
            DisplayName = "SME: Allow DNS"
            Description = "Allow outbound DNS"
            Direction = "Outbound"
            Action = "Allow"
            Protocol = "UDP"
            RemotePort = 53
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @dnsRule -ErrorAction SilentlyContinue | Out-Null

        # Allow HTTP/HTTPS
        $httpRule = @{
            DisplayName = "SME: Allow HTTP/HTTPS"
            Description = "Allow outbound web traffic"
            Direction = "Outbound"
            Action = "Allow"
            Protocol = "TCP"
            RemotePort = @(80, 443)
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @httpRule -ErrorAction SilentlyContinue | Out-Null

        # Allow NTP
        $ntpRule = @{
            DisplayName = "SME: Allow NTP"
            Description = "Allow outbound NTP"
            Direction = "Outbound"
            Action = "Allow"
            Protocol = "UDP"
            RemotePort = 123
            Profile = "Any"
            Group = $groupName
            Enabled = "True"
        }
        New-NetFirewallRule @ntpRule -ErrorAction SilentlyContinue | Out-Null

        Write-LogInfo "Strict outbound rules configured"
        return $true
    }
    catch {
        Write-LogError "Failed to configure outbound rules: $_"
        return $false
    }
}

function Remove-SMERules {
    Write-LogInfo "Removing existing SME Security rules"

    try {
        $smeRules = Get-NetFirewallRule -DisplayName "SME:*" -ErrorAction SilentlyContinue
        foreach ($rule in $smeRules) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue
        }

        Write-LogInfo "Existing SME rules removed"
        return $true
    }
    catch {
        Write-LogError "Failed to remove SME rules: $_"
        return $false
    }
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

function Apply-FirewallHardening {
    Write-LogInfo "Starting Windows Firewall hardening"

    # Backup current rules
    $backupFile = Join-Path $env:TEMP "firewall_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
    Backup-FirewallRules -Path $backupFile

    # Remove existing SME rules
    Remove-SMERules

    # Enable firewall
    Enable-FirewallProfiles

    # Configure logging
    Set-FirewallLogging

    # Remove unnecessary rules
    Remove-UnnecessaryRules

    # Add custom rules
    Add-ManagementRules
    Add-ServiceRules
    Add-BlockRules
    Add-ICMPRules
    Add-IPSecRules
    Set-StrictOutbound

    Write-LogInfo "Windows Firewall hardening completed"

    # Show summary
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "    WINDOWS FIREWALL HARDENING COMPLETED" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuration Summary:" -ForegroundColor Green
    Write-Host "  - Firewall enabled for all profiles"
    Write-Host "  - Default inbound action: Block"
    Write-Host "  - Logging enabled"
    Write-Host "  - Management hosts: $($Script:Config.ManagementHosts -join ', ')"
    Write-Host "  - Trusted networks: $($Script:Config.TrustedNetworks -join ', ')"
    Write-Host ""
    Write-Host "Backup saved to: $backupFile" -ForegroundColor Yellow
    Write-Host ""
}

function Test-FirewallHardening {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "    FIREWALL HARDENING TEST (DRY RUN)" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "The following changes would be applied:" -ForegroundColor Green
    Write-Host ""
    Write-Host "1. Firewall Profiles:" -ForegroundColor Yellow
    Write-Host "   - Enable firewall for Domain, Private, and Public profiles"
    Write-Host "   - Set default inbound action to Block"
    Write-Host "   - Enable logging for blocked connections"
    Write-Host ""
    Write-Host "2. Management Access:" -ForegroundColor Yellow
    foreach ($host in $Script:Config.ManagementHosts) {
        Write-Host "   - Allow RDP, WinRM, SSH from $host"
    }
    Write-Host ""
    Write-Host "3. Service Rules:" -ForegroundColor Yellow
    foreach ($service in $Script:Config.AllowedInboundPorts) {
        $scope = if ($service.ManagementOnly) { "management hosts only" } else { "all" }
        Write-Host "   - $($service.Name) ($($service.Port)/$($service.Protocol)) - $scope"
    }
    Write-Host ""
    Write-Host "4. Block Rules:" -ForegroundColor Yellow
    foreach ($blocked in $Script:Config.BlockedOutboundPorts) {
        Write-Host "   - Block outbound $($blocked.Name) ($($blocked.Port)/$($blocked.Protocol))"
    }
    Write-Host "   - Block SMB to Internet"
    Write-Host "   - Block NetBIOS to Internet"
    Write-Host ""
    Write-Host "Use '-Action Apply' to apply these rules" -ForegroundColor Cyan
    Write-Host ""
}

function Show-FirewallStatus {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "    WINDOWS FIREWALL STATUS" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""

    # Profile status
    Write-Host "Profile Status:" -ForegroundColor Yellow
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked -AutoSize

    # SME rules
    Write-Host "SME Security Rules:" -ForegroundColor Yellow
    $smeRules = Get-NetFirewallRule -DisplayName "SME:*" -ErrorAction SilentlyContinue
    if ($smeRules) {
        $smeRules | Format-Table DisplayName, Enabled, Direction, Action -AutoSize
    } else {
        Write-Host "  No SME Security rules found" -ForegroundColor Gray
    }

    # Active inbound rules
    Write-Host "Active Inbound Allow Rules:" -ForegroundColor Yellow
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { $_.DisplayGroup -notmatch "Core Networking" } |
        Select-Object -First 20 |
        Format-Table DisplayName, Profile -AutoSize

    Write-Host ""
}

function Reset-FirewallRules {
    Write-LogWarn "Resetting Windows Firewall to defaults"

    # Backup first
    $backupFile = Join-Path $env:TEMP "firewall_pre_reset_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
    Backup-FirewallRules -Path $backupFile

    try {
        # Reset to defaults
        netsh advfirewall reset | Out-Null

        Write-LogInfo "Firewall reset to defaults"
        Write-LogInfo "Backup saved to: $backupFile"
    }
    catch {
        Write-LogError "Reset failed: $_"
    }
}

# ============================================================================
# MAIN
# ============================================================================

# Check administrator rights
if (-not (Test-Administrator)) {
    Write-LogError "This script requires administrator privileges"
    Write-Host "Please run PowerShell as Administrator" -ForegroundColor Red
    exit 1
}

# Execute requested action
switch ($Action) {
    'Apply' {
        Apply-FirewallHardening
    }
    'Test' {
        Test-FirewallHardening
    }
    'Backup' {
        Backup-FirewallRules -Path $BackupPath
    }
    'Restore' {
        Restore-FirewallRules -Path $BackupPath
    }
    'Status' {
        Show-FirewallStatus
    }
    'Reset' {
        Reset-FirewallRules
    }
}
