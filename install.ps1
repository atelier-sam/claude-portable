# ============================================================
#  Claude Code Portable - installeur Windows
#  Usage :  irm atelier-sam.fr/cc.ps1 | iex
#  Installe le wizard + Claude + gum + Git portable dans
#  %USERPROFILE%\.claude-portable, et la commande courte "ccp".
#  Aucun secret : tes tokens restent locaux dans config\.
# ============================================================
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$RepoRaw = "https://raw.githubusercontent.com/atelier-sam/claude-portable/main"
$Rel = "https://downloads.claude.ai/claude-code-releases"
$Dir = if ($env:CLAUDE_PORTABLE_DIR) { $env:CLAUDE_PORTABLE_DIR } else { "$env:USERPROFILE\.claude-portable" }
$Plat = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "win32-arm64" } else { "win32-x64" }

Write-Host "Installation de Claude Code Portable dans $Dir ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$Dir\lib","$Dir\bin\$Plat","$Dir\tools\gum\win32-x64","$Dir\git-win" | Out-Null

Write-Host "Recuperation du wizard ..."
foreach ($f in @("Claude.command","lib/common.sh","claude.cmd","claude-classic.cmd")) {
  Invoke-WebRequest "$RepoRaw/$f" -OutFile (Join-Path $Dir ($f -replace '/','\')) -UseBasicParsing
}

$ver = ((Invoke-RestMethod "$Rel/stable") | Out-String).Trim()
Set-Content "$Dir\VERSION" $ver
Write-Host "Telechargement de Claude $ver ($Plat) ..."
Invoke-WebRequest "$Rel/$ver/$Plat/claude.exe" -OutFile "$Dir\bin\$Plat\claude.exe" -UseBasicParsing

Write-Host "Telechargement de l'interface (gum) ..."
$gv = "0.17.0"; $gz = "$env:TEMP\ccp_gum.zip"
Invoke-WebRequest "https://github.com/charmbracelet/gum/releases/download/v$gv/gum_${gv}_Windows_x86_64.zip" -OutFile $gz -UseBasicParsing
$gx = "$env:TEMP\ccp_gumx"; Remove-Item -Recurse -Force $gx -ErrorAction SilentlyContinue
Expand-Archive -Force $gz $gx
Copy-Item ((Get-ChildItem $gx -Recurse -Filter gum.exe | Select-Object -First 1).FullName) "$Dir\tools\gum\win32-x64\gum.exe" -Force

Write-Host "Telechargement de Git portable (pour l'interface) ..."
try {
  $gitUrl = (Invoke-RestMethod "https://api.github.com/repos/git-for-windows/git/releases/latest").assets |
            Where-Object { $_.name -match 'PortableGit.*64-bit\.7z\.exe' } | Select-Object -First 1 -ExpandProperty browser_download_url
  $gitExe = "$env:TEMP\ccp_git.7z.exe"
  Invoke-WebRequest $gitUrl -OutFile $gitExe -UseBasicParsing
  & $gitExe -o"$Dir\git-win" -y | Out-Null
} catch { Write-Host "Git portable: echec (le wizard graphique necessitera Git). $_" -ForegroundColor Yellow }

# Commande courte ccp
$binDir = "$env:USERPROFILE\.local\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Set-Content "$binDir\ccp.cmd"  "@echo off`r`ncall `"$Dir\claude.cmd`" %*"
Set-Content "$binDir\ccp1.cmd" "@echo off`r`nset `"CC_PROFILE=2`"`r`ncall `"$Dir\claude.cmd`" %*"
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if ($userPath -notlike "*$binDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
  Write-Host "$binDir ajoute au PATH (rouvre le terminal)." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "OK. Rouvre un terminal et tape :  ccp" -ForegroundColor Green
