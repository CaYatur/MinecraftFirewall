<#
.SYNOPSIS
    Compiles the optional MinecraftFirewall server plugin into a single jar.

.DESCRIPTION
    Produces plugin\build\MinecraftFirewallBridge.jar, which is what the installer ships and the
    control panel offers to copy into a server's plugins folder.

    Compiled against the Spigot 1.8.8 API and targeting Java 8 bytecode, on purpose. The plugin uses
    only calls that have existed since 1.8, so one jar loads on every Minecraft version this firewall
    supports and on versions that do not exist yet -- which is the whole point of it being optional
    and forward-looking rather than one build per release.

    javac and jar directly rather than Gradle or Maven: there is one source file and one dependency,
    and a build that needs a wrapper to download a build system is a build that breaks when somebody
    is offline.

.PARAMETER ApiJar
    Path to a Spigot/Bukkit API jar. Downloaded and cached if not given.
#>
[CmdletBinding()]
param(
    [string]$ApiJar
)

$ErrorActionPreference = 'Stop'

$here    = $PSScriptRoot
$srcDir  = Join-Path $here 'src\main\java'
$resDir  = Join-Path $here 'src\main\resources'
$outDir  = Join-Path $here 'build'
$classes = Join-Path $outDir 'classes'
$jarPath = Join-Path $outDir 'MinecraftFirewallBridge.jar'

# The exact artifact this was written and verified against. Pinned rather than "latest": the point of
# compiling against an old API is that the result is predictable, and a moving dependency is not.
$apiUrl = 'https://hub.spigotmc.org/nexus/content/repositories/public/org/spigotmc/spigot-api/' +
          '1.8.8-R0.1-SNAPSHOT/spigot-api-1.8.8-R0.1-20160221.082514-43.jar'

if (-not $ApiJar) {
    $cacheDir = Join-Path $env:LOCALAPPDATA 'MinecraftFirewall\build-cache'
    if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Force $cacheDir | Out-Null }

    $ApiJar = Join-Path $cacheDir 'spigot-api-1.8.8.jar'
    if (-not (Test-Path $ApiJar)) {
        Write-Host "Downloading the Spigot 1.8.8 API (once; cached in $cacheDir)"
        Invoke-WebRequest -Uri $apiUrl -OutFile $ApiJar
    }
}

if (-not (Test-Path $ApiJar)) {
    throw "No API jar at $ApiJar."
}

if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Force $classes | Out-Null

$sources = Get-ChildItem -Recurse -Filter *.java $srcDir | ForEach-Object { $_.FullName }

Write-Host "Compiling $($sources.Count) source file(s) against $(Split-Path -Leaf $ApiJar)"

# --release 8 rather than -source/-target: it also checks that only Java 8 APIs are used, so a call
# that would not exist on an older server is caught here rather than on somebody's server.
$javacArgs = @('--release', '8', '-nowarn', '-cp', $ApiJar, '-d', $classes) + $sources
& javac $javacArgs
if ($LASTEXITCODE -ne 0) { throw "javac failed." }

Copy-Item (Join-Path $resDir 'plugin.yml') $classes

Push-Location $classes
try {
    & jar --create --file $jarPath .
    if ($LASTEXITCODE -ne 0) { throw "jar failed." }
}
finally {
    Pop-Location
}

$size = [math]::Round((Get-Item $jarPath).Length / 1KB, 1)
Write-Host "Built $jarPath ($size KB)"
