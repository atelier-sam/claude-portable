# ============================================================
#  Claude Code Portable - installeur Windows
#  Usage :  irm atelier-sam.fr/cc.ps1 | iex
#  Installe le wizard + le noyau ccp-core + Claude + gum + Git portable dans
#  %USERPROFILE%\.claude-portable, et les commandes courtes "ccp" / "ccp1".
#
#  Chaine de confiance (identique a install.sh) :
#   - SHA256SUMS de la derniere release, SIGNE (ssh-keygen -Y verify) ;
#   - chaque fichier du portable verifie contre SHA256SUMS avant d'etre pose ;
#   - claude.exe verifie contre le manifest officiel d'Anthropic ;
#   - gum verifie contre une empreinte epinglee ; Git portable contre le digest
#     publie par l'API GitHub.
#  Toute verification qui echoue ARRETE l'installation.
#  Fichier volontairement en ASCII (pas d'accents) : PowerShell 5.1 lit les
#  scripts sans BOM en ANSI.
# ============================================================
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest est 10x plus lent avec la barre

$CcpDl  = "https://github.com/atelier-sam/claude-portable/releases/latest/download"
$Signer = "ccp-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJP7f3uFSVRqxu997bLbJsDB+J8kerqZglqh5OH3PCS"
$Rel    = "https://downloads.claude.ai/claude-code-releases"
$GumVer = "0.17.0"
$GumSha = "b2be80531c6babc8d4e0e6ca95773d58118a2e1582ae006aace08dbc55503072"
$Dir    = if ($env:CLAUDE_PORTABLE_DIR) { $env:CLAUDE_PORTABLE_DIR } else { "$env:USERPROFILE\.claude-portable" }
$Plat   = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "win32-arm64" } else { "win32-x64" }
$W      = Join-Path $env:TEMP ("ccp-install-" + [guid]::NewGuid().ToString("N"))

function Fail($msg) { Write-Host "X $msg" -ForegroundColor Red; Remove-Item -Recurse -Force $W -ErrorAction SilentlyContinue; exit 1 }
function Ok($msg)   { Write-Host "OK $msg" -ForegroundColor Green }
function Say($msg)  { Write-Host ". $msg" -ForegroundColor Cyan }
function Sha($path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower() }
function Get($url, $out) { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing }

New-Item -ItemType Directory -Force -Path $W, "$Dir\lib", "$Dir\bin\$Plat", "$Dir\bin\win32-x64", "$Dir\tools\gum\win32-x64", "$Dir\git-win" | Out-Null
Say "Installation de Claude Code Portable dans $Dir"

# --- 1) Git portable d'abord si ssh-keygen manque (il en fournit un) ---------
function Install-PortableGit {
  Say "Telechargement de Git portable (interface + outils) ..."
  $rel = Invoke-RestMethod "https://api.github.com/repos/git-for-windows/git/releases/latest" -Headers @{ "User-Agent" = "ccp-install" }
  $asset = $rel.assets | Where-Object { $_.name -match '^PortableGit-.*-64-bit\.7z\.exe$' } | Select-Object -First 1
  if (-not $asset) { Fail "Git portable introuvable dans la release officielle." }
  if (-not $asset.digest -or $asset.digest -notmatch '^sha256:') { Fail "Empreinte de Git portable non publiee : refus." }
  $exe = Join-Path $W "git.7z.exe"
  Get $asset.browser_download_url $exe
  if ((Sha $exe) -ne $asset.digest.Substring(7).ToLower()) { Fail "Empreinte invalide pour Git portable." }
  & $exe -o"$Dir\git-win" -y | Out-Null
  Ok "Git portable verifie et installe"
}
if (-not (Test-Path "$Dir\git-win\bin\bash.exe")) { Install-PortableGit }

$SshKeygen = (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue).Source
if (-not $SshKeygen -and (Test-Path "$Dir\git-win\usr\bin\ssh-keygen.exe")) { $SshKeygen = "$Dir\git-win\usr\bin\ssh-keygen.exe" }
if (-not $SshKeygen) { Fail "ssh-keygen introuvable : impossible d'authentifier la release." }

# --- 2) Sommes signees de la release ----------------------------------------
Get "$CcpDl/SHA256SUMS" "$W\SHA256SUMS"
Get "$CcpDl/SHA256SUMS.sig" "$W\SHA256SUMS.sig"
[IO.File]::WriteAllText("$W\allowed_signers", "$Signer`n")
# Les OCTETS exacts de SHA256SUMS doivent arriver sur stdin : un pipe PowerShell
# re-encode le texte (et cmd /c casse les guillemets imbriques), d'ou Process
# avec ecriture binaire directe dans stdin.
$psi = New-Object Diagnostics.ProcessStartInfo $SshKeygen
$psi.Arguments = "-Y verify -f `"$W\allowed_signers`" -I ccp-release -n file -s `"$W\SHA256SUMS.sig`""
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$proc = [Diagnostics.Process]::Start($psi)
$bytes = [IO.File]::ReadAllBytes("$W\SHA256SUMS")
$proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length); $proc.StandardInput.Close()
$null = $proc.StandardOutput.ReadToEnd(); $null = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
if ($proc.ExitCode -ne 0) { Fail "Signature de la release INVALIDE : installation annulee." }
Ok "Release authentifiee (signature ccp-release)"

$Sums = @{}
foreach ($line in Get-Content "$W\SHA256SUMS") {
  if ($line -match '^([0-9a-f]{64})\s+\*?(.+)$') { $Sums[$Matches[2].Trim()] = $Matches[1] }
}
function Fetch($name, $dest) {
  if (-not $Sums.ContainsKey($name)) { Fail "$name absent de la release." }
  $tmp = Join-Path $W $name
  Get "$CcpDl/$name" $tmp
  if ((Sha $tmp) -ne $Sums[$name]) { Fail "Empreinte invalide pour $name : installation annulee." }
  Move-Item -Force $tmp $dest
}

# --- 3) Fichiers du portable ------------------------------------------------
Say "Recuperation du wizard et du noyau ..."
Fetch "Claude.command"        "$Dir\Claude.command"
Fetch "common.sh"             "$Dir\lib\common.sh"
Fetch "claude.cmd"            "$Dir\claude.cmd"
Fetch "claude-classic.cmd"    "$Dir\claude-classic.cmd"
Fetch "ccp-core-win32-x64.exe" "$Dir\bin\win32-x64\ccp-core.exe"
Ok "Wizard + noyau ccp-core verifies"

# --- 4) Claude Code (manifest officiel) --------------------------------------
$ver = ((Invoke-RestMethod "$Rel/stable") | Out-String).Trim()
$manifest = Invoke-RestMethod "$Rel/$ver/manifest.json"
$want = $manifest.platforms.$Plat.checksum
if (-not $want) { Fail "Empreinte de claude.exe absente du manifest : refus." }
Say "Telechargement de Claude $ver ($Plat) ..."
Get "$Rel/$ver/$Plat/claude.exe" "$W\claude.exe"
if ((Sha "$W\claude.exe") -ne $want.ToLower()) { Fail "Empreinte invalide pour claude.exe : refus." }
Move-Item -Force "$W\claude.exe" "$Dir\bin\$Plat\claude.exe"
Set-Content -NoNewline "$Dir\VERSION" $ver
Ok "Claude $ver verifie (SHA256 du manifest Anthropic)"

# --- 5) Interface gum (empreinte epinglee) -----------------------------------
Say "Telechargement de l'interface (gum) ..."
$gz = "$W\gum.zip"
Get "https://github.com/charmbracelet/gum/releases/download/v$GumVer/gum_${GumVer}_Windows_x86_64.zip" $gz
if ((Sha $gz) -ne $GumSha) { Fail "Empreinte invalide pour gum." }
Expand-Archive -Force $gz "$W\gumx"
Copy-Item ((Get-ChildItem "$W\gumx" -Recurse -Filter gum.exe | Select-Object -First 1).FullName) "$Dir\tools\gum\win32-x64\gum.exe" -Force
Ok "gum verifie"

# --- 6) Commandes courtes ----------------------------------------------------
$binDir = "$env:USERPROFILE\.local\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Set-Content "$binDir\ccp.cmd"  "@echo off`r`ncall `"$Dir\claude.cmd`" %*"
Set-Content "$binDir\ccp1.cmd" "@echo off`r`nset `"CC_PROFILE=2`"`r`ncall `"$Dir\claude.cmd`" %*"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
  Write-Host "$binDir ajoute au PATH (rouvre le terminal)." -ForegroundColor Yellow
}
Remove-Item -Recurse -Force $W -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "OK. Rouvre un terminal et tape :  ccp" -ForegroundColor Green
Write-Host "Tout est range dans $Dir (sessions comprises)."
