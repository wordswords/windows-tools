# Runs a script (deploy or generator) in this process with mocks loaded.
# Arguments are read from a JSON array file and splatted as named parameters.
param(
    [string]$MockPath,
    [string]$DeployPath,
    [string]$ArgsFile
)
if ($MockPath) { . $MockPath }
$argList = @(Get-Content -LiteralPath $ArgsFile -Raw | ConvertFrom-Json)
$splat = @{}
for ($i = 0; $i -lt $argList.Count; $i++) {
    $a = [string]$argList[$i]
    if ($a -like '-*') {
        $key = $a.TrimStart('-')
        $val = $true
        if (($i + 1) -lt $argList.Count -and ("$($argList[$i + 1])" -notlike '-*')) {
            $val = $argList[$i + 1]
            $i++
        }
        $splat[$key] = $val
    }
}
& $DeployPath @splat
exit $LASTEXITCODE
