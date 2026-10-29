$paths = @(
    "$env:windir\System32\msiexec.exe",
    "$env:windir\SysWOW64\msiexec.exe"
)

$paths | ForEach-Object {
    New-NetFirewallRule `
        -DisplayName "Block MSI Egress" `
        -Direction Outbound `
        -Program $_ `
        -Action Block
}
