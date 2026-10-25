@echo off
chcp 65001 >nul
title Labo Photo Almas - Centre de Commande Web

:MENU
cls
echo =====================================================================
echo           LABO PHOTO ALMAS - CENTRE DE LANCEMENT DU SITE WEB
echo =====================================================================
echo.
echo   [1] Demarrer le Site en Production (Serveur Securise - Port 3000)
echo   [2] Demarrer le Mode Developpement (Vite Hot-Reload - Port 5173)
echo   [3] Recompiler le Bundle de Production (npm run build)
echo   [4] Lancer l'Audit d'Integrite et les Tests de Securite
echo   [5] Quitter
echo.
echo =====================================================================
set /p choice="Choisissez une option [1-5] (Defaut: 1): "

if "%choice%"=="" set choice=1
if "%choice%"=="1" goto PROD
if "%choice%"=="2" goto DEV
if "%choice%"=="3" goto BUILD
if "%choice%"=="4" goto AUDIT
if "%choice%"=="5" goto EXIT
echo Choix invalide. Veuillez reessayer.
timeout /t 2 >nul
goto MENU

:PROD
cls
echo =====================================================================
echo   Lancement du Serveur de Production Labo Photo Almas
echo =====================================================================
if not exist dist\index.html (
    echo [Info] Compilation prealable du bundle...
    call npm run build
)
echo Ouverture automatique de http://localhost:3000/ ...
start "" http://localhost:3000/
node server.js
goto MENU

:DEV
cls
echo =====================================================================
echo   Lancement du Serveur Vite Developpement avec Hot-Reload
echo =====================================================================
echo Ouverture automatique de http://localhost:5173/ ...
call npm run start:dev
goto MENU

:BUILD
cls
echo =====================================================================
echo   Recompilation de Production (Vite)
echo =====================================================================
call npm run build
echo.
echo Compilation terminee avec succes.
pause
goto MENU

:AUDIT
cls
echo =====================================================================
echo   Audit d'Integrite et Tests de Cybersecurite
echo =====================================================================
call npm test
echo.
call npm run audit
echo.
pause
goto MENU

:EXIT
exit
