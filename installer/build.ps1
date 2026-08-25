<#
.SYNOPSIS
    Publishes MinecraftFirewall and compiles the Windows installer.

.DESCRIPTION
    Produces publish\MinecraftFirewall-<version>-setup.exe.

    All three executables are published self-contained into a single directory on purpose. They share
    one .NET runtime copy, which keeps the download roughly the size of one app rather than three, and
    more importantly it means the machine needs nothing pre-installed: the most common way a Windows
    install of a .NET app fails is a missing or mismatched runtime, and there is nobody to talk that
    through on a game server someone set up over a weekend.

    Publishing into one directory also matters at runtime, not just for packaging — the control panel
    locates the service executable and appsettings.json relative to its own folder.

.PARAMETER Version
    Overrides the version compiled into the installer. Must match the AppVersion in
    MinecraftFirewall.iss, which is the value used when it is not passed.
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot  = Split-Path -Parent $PSScriptRoot
$publishTo = Join-Path $repoRoot 'publish\app'
$issFile   = Join-Path $PSScriptRoot 'MinecraftFirewall.iss'

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    throw "Inno Setup 6 was not found. Install it from https://jrsoftware.org/isdl.php, then run this again."
}

# A stale file from a previous build would be packaged as though it belonged, so this starts clean
# rather than publishing over whatever is there.
if (Test-Path $publishTo) {
    Remove-Item $publishTo -Recurse -Force
}

# The control panel is published last so that, where the three overlap on shared runtime files, the
# copies that survive are the ones its own build produced.
$projects = @(
    'src\MinecraftFirewall.Proxy\MinecraftFirewall.Proxy.csproj',
    'src\MinecraftFirewall.Admin\MinecraftFirewall.Admin.csproj',
    'src\MinecraftFirewall.App\MinecraftFirewall.App.csproj'
)

foreach ($project in $projects) {
    Write-Host "Publishing $project" -ForegroundColor Cyan
    & dotnet publish (Join-Path $repoRoot $project) `
        -c $Configuration -r $Runtime --self-contained true -o $publishTo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $project" }
}

foreach ($required in @('MinecraftFirewall.exe', 'MinecraftFirewall.Proxy.exe', 'appsettings.json')) {
    if (-not (Test-Path (Join-Path $publishTo $required))) {
        throw "Publish output is missing $required — the installer would produce a broken install."
    }
}

Write-Host "Compiling the installer" -ForegroundColor Cyan
$isccArgs = @($issFile)
if ($Version) { $isccArgs += "/DAppVersion=$Version" }

& $iscc $isccArgs
if ($LASTEXITCODE -ne 0) { throw 'ISCC failed.' }

Get-ChildItem (Join-Path $repoRoot 'publish\*-setup.exe') |
    ForEach-Object { Write-Host ("Built {0} ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) -ForegroundColor Green }
