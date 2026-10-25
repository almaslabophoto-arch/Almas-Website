@echo off
chcp 65001 >nul
title Labo Photo Almas - Lancement du Site Web

echo ==========================================================
echo   LABO PHOTO ALMAS - DEMARRAGE DU SITE WEB
echo ==========================================================
echo.

if not exist dist\index.html (
    echo [Info] Generation initiale du bundle de production...
    call npm run build
    echo.
)

echo [1/2] Lancement du serveur securise sur le port 3000...
start "" http://localhost:3000/

echo [2/2] Le site s'ouvre dans votre navigateur par defaut.
echo Serveur actif. Fermez cette fenetre pour arreter le serveur.
echo.

node server.js
pause
