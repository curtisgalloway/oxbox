# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0

# Stage the Windows payload and build the per-user MSI (WiX v7).
#
#   packaging\windows\build.ps1 -Version 0.3.0 -OutDir dist
#
# Requires the WiX CLI:  dotnet tool install --global wix
# (and `wix eula accept wix7` once per machine, or the first build dies with
# WIX7015 -- the Open Source Maintenance Fee EULA, whose fee applies only to
# consumers generating revenue, which this is not).
#
# The staged layout is the same prefix the .deb and the macOS tarball install,
# because find_skill knows exactly one rule: ..\share\oxbox from the script's
# own directory. What is different on Windows is bin\, which holds each tool
# twice -- the extensionless Python script, and a .cmd shim beside it, because
# Windows cannot execute a shebang. The shim is what the PATH entry makes
# typeable; the script is what it runs.
#
# jail.sb is deliberately absent: there is no jail on native Windows and
# oxbox refuses rather than pretending. It is packaged anyway, refusal and
# all, so that `oxbox --skill` answers and the four tools stay one set.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$Windows = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Windows "..\..")).Path

# ProductVersion has to be three numeric fields. A tag build already is one;
# a workflow_dispatch build is something like 0.0.0~dev.1a2b3c4, which msi
# cannot express, so it becomes 0.0.0 and says so. The tools' own VERSION is
# unaffected either way -- it is baked into the scripts, not passed in here.
if ($Version -match '^\d+\.\d+\.\d+$') {
    $MsiVersion = $Version
} else {
    $MsiVersion = '0.0.0'
    Write-Host "::warning::'$Version' is not a three-field MSI version; building as $MsiVersion"
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path
$Stage = Join-Path $OutDir "stage"
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }

$BinDir = Join-Path $Stage "bin"
$SkillDir = Join-Path $Stage "share\oxbox\ox-review"
$ScriptsDir = Join-Path $SkillDir "scripts"
$DocDir = Join-Path $Stage "doc"
foreach ($dir in @($BinDir, $ScriptsDir, $DocDir)) {
    New-Item -ItemType Directory -Force $dir | Out-Null
}

$Tools = @("ox", "oxbox", "oxapply", "oxseed")

# %~dp0 ends in a backslash, so "%~dp0ox" is the script beside this shim.
# No parenthesised blocks anywhere: %errorlevel% inside one expands when the
# block is parsed rather than when it runs, which would report the exit code
# of whatever ran before the tool instead of the tool's own. Labels avoid the
# whole question. The exit code matters here more than usual -- oxbox exits 78
# on Windows by design, and a shim that swallowed that would turn a refusal
# into an apparent success.
$ShimTemplate = @'
@echo off
setlocal
where py >nul 2>&1
if not errorlevel 1 goto usepy
where python >nul 2>&1
if not errorlevel 1 goto usepython
>&2 echo __TOOL__: no Python found on PATH. oxbox needs Python 3.9 or newer.
>&2 echo __TOOL__: try: winget install Python.Python.3.13
exit /b 78
:usepy
py -3 "%~dp0__TOOL__" %*
exit /b %errorlevel%
:usepython
python "%~dp0__TOOL__" %*
exit /b %errorlevel%
'@

foreach ($tool in $Tools) {
    Copy-Item (Join-Path $Repo $tool) (Join-Path $BinDir $tool)
    $shim = $ShimTemplate -replace '__TOOL__', $tool
    # Written as CRLF ASCII on purpose: a batch file is read by cmd.exe, not
    # by Python, and LF-only labels are a known way to make goto misbehave.
    $lines = ($shim -split "`n") | ForEach-Object { $_.TrimEnd("`r") }
    [System.IO.File]::WriteAllText(
        (Join-Path $BinDir "$tool.cmd"),
        (($lines -join "`r`n") + "`r`n"),
        [System.Text.Encoding]::ASCII)
}

Copy-Item (Join-Path $Repo ".claude\skills\ox-review\SKILL.md") (Join-Path $SkillDir "SKILL.md")
foreach ($script in @("preflight.py", "exposure.py", "oxreview.py")) {
    Copy-Item (Join-Path $Repo ".claude\skills\ox-review\scripts\$script") (Join-Path $ScriptsDir $script)
}
Copy-Item (Join-Path $Repo "LICENSE") (Join-Path $DocDir "LICENSE")
Copy-Item (Join-Path $Repo "README.md") (Join-Path $DocDir "README.md")

# -arch x86, for a package that contains no machine code at all. An x86 MSI
# installs on x86, x64 and arm64 Windows alike; an x64 one narrows that for
# nothing, and there is no "neutral" to ask for. Nothing lands in a
# Program Files (x86) directory either way, because the install is per-user
# under LocalAppData.
$Msi = Join-Path $OutDir "oxbox-$MsiVersion.msi"
& wix build -arch x86 `
    -d "Version=$MsiVersion" -d "StageDir=$Stage" `
    (Join-Path $Windows "Package.wxs") -o $Msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "built $Msi"
