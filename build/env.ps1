# Toolchain settings shared by build.ps1 and test.ps1.
# Override any value in build/env.local.ps1 (ignored by git); see env.local.example.ps1.

$localSettings = Join-Path $PSScriptRoot 'env.local.ps1'
if (Test-Path $localSettings) { . $localSettings }

function Set-DefaultVariable([string] $Name, [scriptblock] $Value) {
  if (-not [Environment]::GetEnvironmentVariable($Name, 'Process')) {
    [Environment]::SetEnvironmentVariable($Name, (& $Value), 'Process')
  }
}

function Get-NewestGccVersion([string] $SdkRoot) {
  $gccRoot = Join-Path $SdkRoot 'usr\lib\gcc\x86_64-linux-gnu'
  if (-not (Test-Path $gccRoot)) { return '' }
  Get-ChildItem $gccRoot -Directory |
    Sort-Object { [int]($_.Name -replace '\D.*$', '') } |
    Select-Object -Last 1 -ExpandProperty Name
}

Set-DefaultVariable 'BDS_ROOT'       { 'C:\Program Files (x86)\Embarcadero\Studio\37.0' }
Set-DefaultVariable 'BDS_COMMON'     { 'C:\Users\Public\Documents\Embarcadero\Studio\37.0' }
Set-DefaultVariable 'LINUX_SDK_ROOT' { Join-Path $env:USERPROFILE 'Documents\Embarcadero\Studio\SDKs\ubuntu26.04.sdk' }
Set-DefaultVariable 'LINUX_GCC_VERSION' { Get-NewestGccVersion $env:LINUX_SDK_ROOT }
Set-DefaultVariable 'LINUX_SDK_LIBPATH' {
  $libraryFolders = @(
    "usr\lib\gcc\x86_64-linux-gnu\$($env:LINUX_GCC_VERSION)",
    'usr\lib\x86_64-linux-gnu',
    'lib\x86_64-linux-gnu',
    'lib64'
  ) | ForEach-Object { Join-Path $env:LINUX_SDK_ROOT $_ }
  $libraryFolders -join ';'
}
Set-DefaultVariable 'WSL_DISTRO' { 'Ubuntu' }
