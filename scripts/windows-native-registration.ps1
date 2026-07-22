param(
    [switch]$Repair
)

$ErrorActionPreference = "Stop"
$HostName = "com.pwdvault.app"
$Subkey = "Software\Google\Chrome\NativeMessagingHosts\$HostName"
$ExpectedManifest = Join-Path $env:LOCALAPPDATA "PwdVault\com.pwdvault.app.chrome.json"
$ExpectedOrigin = "chrome-extension://kekeibdcccjakipnmdpbafhaeknioaem/"
$Views = @(
    [Microsoft.Win32.RegistryView]::Registry32,
    [Microsoft.Win32.RegistryView]::Registry64
)

function Get-Registration([Microsoft.Win32.RegistryView]$View) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::CurrentUser,
        $View
    )
    try {
        $key = $base.OpenSubKey($Subkey)
        if ($null -eq $key) {
            return [pscustomobject]@{
                View = $View.ToString()
                Manifest = $null
                ManifestExists = $false
                Host = $null
                HostExists = $false
                Allowed = $false
            }
        }
        try {
            $manifestPath = [string]$key.GetValue("")
        } finally {
            $key.Dispose()
        }
    } finally {
        $base.Dispose()
    }

    $manifestExists = -not [string]::IsNullOrWhiteSpace($manifestPath) -and
        (Test-Path -LiteralPath $manifestPath -PathType Leaf)
    $hostPath = $null
    $hostExists = $false
    $allowed = $false
    if ($manifestExists) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            $hostPath = [string]$manifest.path
            $hostExists = -not [string]::IsNullOrWhiteSpace($hostPath) -and
                (Test-Path -LiteralPath $hostPath -PathType Leaf)
            $allowed = @($manifest.allowed_origins) -contains $ExpectedOrigin
        } catch {
            # Invalid JSON is reported through the false fields below.
        }
    }

    [pscustomobject]@{
        View = $View.ToString()
        Manifest = $manifestPath
        ManifestExists = $manifestExists
        Host = $hostPath
        HostExists = $hostExists
        Allowed = $allowed
    }
}

if ($Repair) {
    if (-not (Test-Path -LiteralPath $ExpectedManifest -PathType Leaf)) {
        throw "Expected Chrome Native Messaging manifest is missing: $ExpectedManifest"
    }
    $candidate = Get-Content -LiteralPath $ExpectedManifest -Raw | ConvertFrom-Json
    if ($candidate.name -ne $HostName) {
        throw "Unexpected Native Messaging host name in $ExpectedManifest"
    }
    if (-not (@($candidate.allowed_origins) -contains $ExpectedOrigin)) {
        throw "Stable Chrome extension origin is missing from $ExpectedManifest"
    }
    if (-not (Test-Path -LiteralPath ([string]$candidate.path) -PathType Leaf)) {
        throw "Native Messaging executable is missing: $($candidate.path)"
    }

    foreach ($view in $Views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            $view
        )
        try {
            $key = $base.CreateSubKey($Subkey)
            try {
                $key.SetValue("", $ExpectedManifest, [Microsoft.Win32.RegistryValueKind]::String)
            } finally {
                $key.Dispose()
            }
        } finally {
            $base.Dispose()
        }
    }
    Write-Output "Repaired Chrome Native Messaging registration in Registry32 and Registry64."
}

$results = @($Views | ForEach-Object { Get-Registration $_ })
$results | Format-Table -AutoSize

$valid = @($results | Where-Object {
    $_.ManifestExists -and $_.HostExists -and $_.Allowed
})
if ($valid.Count -ne 2) {
    Write-Error "Chrome Native Messaging registration is not valid in both registry views."
    exit 1
}

$paths = @($results | ForEach-Object { $_.Manifest } | Select-Object -Unique)
if ($paths.Count -ne 1) {
    Write-Error "Registry32 and Registry64 point to different Native Messaging manifests."
    exit 1
}

Write-Output "Chrome Native Messaging registration: PASS"
