# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0

# Stage the Windows payload and build the per-user MSI (WiX v7).
#
#   packaging\windows\build.ps1 -Version 1.0.0 -OutDir dist -BinDir target\release
#
# Requires the WiX CLI:  dotnet tool install --global wix
# (and `wix eula accept wix7` once per machine, or the first build dies with
# WIX7015 -- the Open Source Maintenance Fee EULA, whose fee applies only to
# consumers generating revenue, which this is not).
#
# The staged layout is the same prefix the .deb and the tarballs install:
# oxbox.exe in bin\, the four helpers it runs in libexec\bin\ (helper_dirs
# finds them at ..\libexec\bin from oxbox.exe), and the skill under
# share\oxbox, which the skill lookup resolves one, two or three levels up
# from whichever executable asks. Native executables, so no shim: the PATH
# entry makes oxbox typeable by itself.
#
# jail.sb is deliberately absent: there is no jail on native Windows and
# oxbox refuses rather than pretending. It is packaged anyway, refusal and
# all, so that `oxbox --skill` answers and the five tools stay one set.

param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$OutDir = "dist",
    [string]$BinDir = "target\release"
)

$ErrorActionPreference = "Stop"

$Windows = $PSScriptRoot
$Repo = (Resolve-Path (Join-Path $Windows "..\..")).Path
$BinDir = (Resolve-Path $BinDir).Path

# ProductVersion has to be three numeric fields. A tag build already is one;
# a workflow_dispatch build is something like 0.0.0~dev.1a2b3c4, which msi
# cannot express, so it becomes 0.0.0 and says so. The tools' own version is
# unaffected either way -- it is compiled into the binaries, not passed in
# here.
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

$BinStage = Join-Path $Stage "bin"
$LibexecDir = Join-Path $Stage "libexec\bin"
$SkillDir = Join-Path $Stage "share\oxbox\ox-review"
$ScriptsDir = Join-Path $SkillDir "scripts"
$DocDir = Join-Path $Stage "doc"
$DocDocsDir = Join-Path $DocDir "docs"
foreach ($dir in @($BinStage, $LibexecDir, $ScriptsDir, $DocDocsDir)) {
    New-Item -ItemType Directory -Force $dir | Out-Null
}

Copy-Item (Join-Path $BinDir "oxbox.exe") (Join-Path $BinStage "oxbox.exe")
foreach ($helper in @("oxbox-sandbox", "oxbox-send", "oxbox-patch", "oxbox-jail")) {
    Copy-Item (Join-Path $BinDir "$helper.exe") (Join-Path $LibexecDir "$helper.exe")
}

Copy-Item (Join-Path $Repo ".claude\skills\ox-review\SKILL.md") (Join-Path $SkillDir "SKILL.md")
foreach ($script in @("preflight.py", "exposure.py", "oxreview.py")) {
    Copy-Item (Join-Path $Repo ".claude\skills\ox-review\scripts\$script") (Join-Path $ScriptsDir $script)
}
Copy-Item (Join-Path $Repo "LICENSE") (Join-Path $DocDir "LICENSE")
Copy-Item (Join-Path $Repo "README.md") (Join-Path $DocDir "README.md")
# Under docs\ beside the README, so its relative link resolves when installed.
Copy-Item (Join-Path $Repo "docs\comparison.md") (Join-Path $DocDocsDir "comparison.md")

# -arch x64: the binaries are x86_64, built on the x64 runner. An arm64
# Windows build would be a second MSI from a second target, not this one
# with a different flag. Nothing lands in a Program Files (x86) directory
# either way, because the install is per-user under LocalAppData.
$Msi = Join-Path $OutDir "oxbox-$MsiVersion-x64.msi"
& wix build -arch x64 `
    -d "Version=$MsiVersion" -d "StageDir=$Stage" `
    (Join-Path $Windows "Package.wxs") -o $Msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "built $Msi"
