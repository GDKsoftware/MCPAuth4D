# Builds Tests/MCPAuth.Tests.dpr and runs it; exits non-zero when the build or a test fails.
#   powershell -File build/test.ps1 [-Platform Win64|Linux64]
# Linux64 tests run inside WSL (distro from WSL_DISTRO, see env.ps1) against the system libcrypto.so.3.
param([ValidateSet('Win64', 'Linux64')] [string] $Platform = 'Win64')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1')

$root = Split-Path $PSScriptRoot -Parent
$testProject = 'Tests/MCPAuth.Tests.dpr'
$testProgram = [IO.Path]::GetFileNameWithoutExtension($testProject)
$outputFolder = "$root\bin\$Platform\Debug"

try {
  & (Join-Path $PSScriptRoot 'build.ps1') -Project $testProject -Platform $Platform -Config Debug
}
catch {
  Write-Host $_.Exception.Message
  exit 2
}

if ($Platform -eq 'Linux64') {
  $windowsPath = (Join-Path $outputFolder $testProgram) -replace '\\', '/'
  $linuxPath = wsl -d $env:WSL_DISTRO -- wslpath -a "$windowsPath"
  wsl -d $env:WSL_DISTRO -- "$linuxPath" '-exit:continue'
}
else {
  & (Join-Path $outputFolder "$testProgram.exe") '-exit:continue' "-xml:$outputFolder\test-results.xml"
}

$testExitCode = $LASTEXITCODE
if ($testExitCode -ne 0) {
  Write-Host "Tests failed on $Platform (exit $testExitCode)"
  exit $testExitCode
}
Write-Host "All tests passed on $Platform"
