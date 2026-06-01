@echo off
REM ============================================================
REM   CLAUDE CODE PORTABLE - wizard Windows (interface gum)
REM   Couleur Atelier de Sam (#D84D2B). Source ASCII pur ;
REM   gum.exe = titre + menu fleche. Table = colonnes alignees.
REM ============================================================
chcp 65001 >nul 2>&1
setlocal enableextensions enabledelayedexpansion
set "ROOT=%~dp0"
title Claude Code Portable
set "REL=https://downloads.claude.ai/claude-code-releases"
set "OR=#D84D2B"
set "PLAT=win32-x64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PLAT=win32-arm64"
if /I "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "PLAT=win32-arm64"
set "BIN=%ROOT%bin\%PLAT%\claude.exe"
set "GUM=%ROOT%tools\gum\win32-x64\gum.exe"
if not exist "%ROOT%logs" md "%ROOT%logs" >nul 2>&1
set "LOG=%ROOT%logs\windows.log"
set "SELF=%TEMP%\cc_sel.txt"

if not exist "%GUM%" goto plainfallback

:menu
cls
set "VER=?"
if exist "%ROOT%VERSION" set /p VER=<"%ROOT%VERSION"
set "ACTIVE=1"
if exist "%ROOT%ACTIVE" set /p ACTIVE=<"%ROOT%ACTIVE"
"%GUM%" style --border rounded --border-foreground "%OR%" --padding "0 2" --margin "1 0 1 2" --align center --foreground "%OR%" --bold "CLAUDE CODE PORTABLE" "v!VER! - Windows (%PLAT%) - bypass ON"
echo    COMPTES
echo.
set "TOTAL=0"
set "CONN=0"
set "NB=0"
set "ANY="
for /d %%D in ("%ROOT%config\*") do (
  set "N=%%~nxD"
  set "ANY=1"
  set /a NB+=1
  set "CNT=0"
  for /f %%C in ('dir /s /b "%%D\projects\*.jsonl" 2^>nul ^| findstr /v /c:"\._" ^| find /c /v ""') do set "CNT=%%C"
  set /a TOTAL+=CNT
  set "PROJ=0"
  for /f %%P in ('dir /b /ad "%%D\projects" 2^>nul ^| findstr /v /c:"._" ^| find /c /v ""') do set "PROJ=%%P"
  set "ST=pas de token"
  if exist "%%D\oauth.token" ( set "ST=connecte   " & set /a CONN+=1 )
  set "STAR= "
  if /I "!N!"=="!ACTIVE!" set "STAR=*"
  set "V="
  if exist "%%D\.verified" set "V=  [OK valide]"
  if exist "%%D\.failed" set "V=  [X rejete]"
  echo       !STAR! !N!    !ST!    !CNT! sess   !PROJ! proj!V!
)
if not defined ANY echo       (aucun - choisis "Ajouter un compte")
echo.
echo    !NB! compte(s)  -  !CONN! connecte(s)  -  !TOTAL! sessions
echo.

"%GUM%" choose --cursor "> " --cursor.foreground "%OR%" "Lancer le compte actif" "Lancer un autre compte" "Verifier la connexion" "Ajouter un compte" "Compte par defaut" "Statistiques detaillees" "Mettre a jour" "Tout effacer" "Quitter" > "%SELF%"
set "SEL="
set /p SEL=<"%SELF%"
if "!SEL!"=="Lancer le compte actif" goto launch
if "!SEL!"=="Lancer un autre compte" goto launchother
if "!SEL!"=="Verifier la connexion" goto verify
if "!SEL!"=="Ajouter un compte" goto add
if "!SEL!"=="Compte par defaut" goto setdef
if "!SEL!"=="Statistiques detaillees" goto stats
if "!SEL!"=="Mettre a jour" goto update
if "!SEL!"=="Tout effacer" goto wipe
if "!SEL!"=="Quitter" goto quit
goto menu

:launchother
cls
del "%SELF%" 2>nul
( for /d %%D in ("%ROOT%config\*") do @echo %%~nxD ) > "%TEMP%\cc_accts.txt"
type "%TEMP%\cc_accts.txt" | "%GUM%" choose --header "Quel compte lancer ?" --cursor "> " --cursor.foreground "%OR%" > "%SELF%"
set "ACTIVE="
set /p ACTIVE=<"%SELF%"
if not defined ACTIVE goto menu
goto launch

:launch
cls
set "PROFILE=!ACTIVE!"
if not exist "%BIN%" (
  >>"%LOG%" echo [%DATE% %TIME%] ERREUR binaire absent: %BIN%
  "%GUM%" style --foreground 203 "Binaire introuvable. Tape 'Mettre a jour' ou verifie la cle."
  pause & goto menu
)
set "CLAUDE_CONFIG_DIR=%ROOT%config\!PROFILE!"
if not exist "!CLAUDE_CONFIG_DIR!" md "!CLAUDE_CONFIG_DIR!" >nul 2>&1
if not exist "!CLAUDE_CONFIG_DIR!\settings.json" (
  >"!CLAUDE_CONFIG_DIR!\settings.json" (
    echo {
    echo   "defaultMode": "bypassPermissions",
    echo   "skipDangerousModePermissionPrompt": true,
    echo   "env": { "DISABLE_AUTOUPDATER": "1" }
    echo }
  )
)
set "DISABLE_AUTOUPDATER=1"
set "CLAUDE_CODE_OAUTH_TOKEN="
if exist "!CLAUDE_CONFIG_DIR!\oauth.token" set /p CLAUDE_CODE_OAUTH_TOKEN=<"!CLAUDE_CONFIG_DIR!\oauth.token"
if exist "%ROOT%git-win\cmd\git.exe" (
  set "PATH=%ROOT%git-win\cmd;%ROOT%git-win\mingw64\bin;%ROOT%git-win\usr\bin;%PATH%"
  set "CLAUDE_CODE_GIT_BASH_PATH=%ROOT%git-win\bin\bash.exe"
)
>>"%LOG%" echo(
>>"%LOG%" echo [%DATE% %TIME%] lancement profil=!PROFILE! plat=%PLAT%
if defined CLAUDE_CODE_OAUTH_TOKEN (>>"%LOG%" echo [info] token charge) else (>>"%LOG%" echo [info] AUCUN token)
"%BIN%" --version >>"%LOG%" 2>&1
"%GUM%" style --foreground "%OR%" --bold --margin "1 0 1 2" "Compte !PROFILE! - bypass ON - demarrage... (tape /status dans Claude pour email + quota)"
"%BIN%" --dangerously-skip-permissions
>>"%LOG%" echo [%DATE% %TIME%] fin code=!ERRORLEVEL!
goto menu

:verify
cls
set "P=!ACTIVE!"
set "TF=%ROOT%config\!P!\oauth.token"
if not exist "!TF!" ( "%GUM%" style --foreground 203 "Compte !P! : aucun token a verifier." & pause & goto menu )
"%GUM%" style --foreground "%OR%" --bold --margin "1 0 1 2" "Verification du compte !P! (petit appel test)..."
set "CLAUDE_CODE_OAUTH_TOKEN="
set /p CLAUDE_CODE_OAUTH_TOKEN=<"!TF!"
set "CLAUDE_CONFIG_DIR=%ROOT%config\!P!"
set "DISABLE_AUTOUPDATER=1"
"%BIN%" -p "Reponds: OK" --output-format text <nul > "%TEMP%\cc_v.txt" 2>&1
if errorlevel 1 goto verifyfail
findstr /i "invalid expired unauthor authentication error 401 403" "%TEMP%\cc_v.txt" >nul && goto verifyfail
del "%ROOT%config\!P!\.failed" 2>nul
> "%ROOT%config\!P!\.verified" echo ok
"%GUM%" style --foreground 42 --bold "OK : le compte !P! fonctionne (token valide)."
pause
goto menu
:verifyfail
del "%ROOT%config\!P!\.verified" 2>nul
> "%ROOT%config\!P!\.failed" echo fail
"%GUM%" style --foreground 203 --bold "Echec : le compte !P! ne repond pas (token invalide/expire ?)."
pause
goto menu

:add
cls
"%GUM%" style --border rounded --border-foreground "%OR%" --padding "0 2" --margin "1 0 1 2" --foreground "%OR%" --bold "AJOUTER / RECONNECTER UN COMPTE"
"%GUM%" style --foreground 244 --margin "0 0 1 2" "Connecte-toi dans le navigateur, puis copie le token (sk-ant-oat...)."
set "NAME="
set /p "NAME=   Nom du compte (ex 1, 2): "
if not defined NAME goto menu
"%BIN%" setup-token
set "TOK="
set /p "TOK=   Colle le token puis Entree: "
if not defined TOK ( "%GUM%" style --foreground 203 "Aucun token. Rien enregistre." & pause & goto menu )
echo !TOK!| findstr /b "sk-ant-" >nul
if errorlevel 1 ( "%GUM%" style --foreground 203 "Pas un token (attendu sk-ant-...). Rien enregistre." & pause & goto menu )
if not exist "%ROOT%config\!NAME!" md "%ROOT%config\!NAME!" >nul 2>&1
<nul set /p="!TOK!">"%ROOT%config\!NAME!\oauth.token"
del "%ROOT%config\!NAME!\.verified" "%ROOT%config\!NAME!\.failed" 2>nul
>"%ROOT%ACTIVE" echo !NAME!
"%GUM%" style --foreground 42 --bold "Compte !NAME! enregistre. Utilise 'Verifier la connexion' pour confirmer."
pause
goto menu

:setdef
cls
del "%TEMP%\cc_accts.txt" 2>nul
( for /d %%D in ("%ROOT%config\*") do @echo %%~nxD ) > "%TEMP%\cc_accts.txt"
type "%TEMP%\cc_accts.txt" | "%GUM%" choose --header "Compte par defaut ?" --cursor "> " --cursor.foreground "%OR%" > "%SELF%"
set "NEW="
set /p NEW=<"%SELF%"
if defined NEW >"%ROOT%ACTIVE" echo !NEW!
goto menu

:stats
cls
"%GUM%" style --border double --border-foreground "%OR%" --padding "1 3" --margin "1 0 1 2" --foreground "%OR%" --bold "STATISTIQUES DETAILLEES"
echo    Version Claude Code : !VER!
echo    Plateforme          : Windows (%PLAT%)
echo    Comptes : !NB!    Connectes : !CONN!    Sessions : !TOTAL!
echo.
"%GUM%" style --foreground 244 "Email et quota ne sont pas exposes hors de Claude."
"%GUM%" style --foreground 244 "Lance un compte puis tape /status dans Claude pour les voir en direct."
pause
goto menu

:update
cls
"%GUM%" style --foreground "%OR%" --bold --margin "1 0 1 2" "Mise a jour de Claude Code..."
curl -fsSL "%REL%/stable" -o "%TEMP%\ccver.txt"
if errorlevel 1 ( "%GUM%" style --foreground 203 "Pas de reseau." & pause & goto menu )
set /p NV=<"%TEMP%\ccver.txt"
if not exist "%ROOT%bin\%PLAT%" md "%ROOT%bin\%PLAT%" >nul 2>&1
curl -fsSL "%REL%/!NV!/%PLAT%/claude.exe" -o "%ROOT%bin\%PLAT%\claude.exe.new"
if errorlevel 1 ( "%GUM%" style --foreground 203 "Echec du telechargement." & pause & goto menu )
move /y "%ROOT%bin\%PLAT%\claude.exe.new" "%ROOT%bin\%PLAT%\claude.exe" >nul
>"%ROOT%VERSION" echo !NV!
"%GUM%" style --foreground 42 "Mis a jour: !NV!"
pause
goto menu

:wipe
cls
"%GUM%" confirm "Tout deconnecter et effacer les sessions de la cle ?"
if errorlevel 1 ( "%GUM%" style --foreground 244 "Annule." & timeout /t 1 >nul & goto menu )
if exist "%ROOT%config" rd /s /q "%ROOT%config"
md "%ROOT%config" >nul 2>&1
if exist "%ROOT%ACTIVE" del /q "%ROOT%ACTIVE"
"%GUM%" style --foreground 42 "Efface. Revoque le token sur claude.ai si besoin."
pause
goto menu

:plainfallback
echo Interface gum absente pour cette plateforme.
echo Lancement direct du compte par defaut...
set "ACTIVE=1"
if exist "%ROOT%ACTIVE" set /p ACTIVE=<"%ROOT%ACTIVE"
set "CLAUDE_CONFIG_DIR=%ROOT%config\%ACTIVE%"
set "CLAUDE_CODE_OAUTH_TOKEN="
if exist "%CLAUDE_CONFIG_DIR%\oauth.token" set /p CLAUDE_CODE_OAUTH_TOKEN=<"%CLAUDE_CONFIG_DIR%\oauth.token"
set "DISABLE_AUTOUPDATER=1"
"%BIN%" --dangerously-skip-permissions
goto quit

:quit
endlocal
