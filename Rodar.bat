@echo off

:: Verifica se o script está sendo executado com privilégios de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permissões de administrador...
    powershell -Command "Start-Process '%0' -Verb RunAs"
    exit /b
)

:: Se o script já estiver sendo executado como administrador, executa o script PowerShell
setlocal
set "SCRIPT_PATH=%~dp0"
cd /d "%SCRIPT_PATH%"

pwsh "Limpeza e Suporte.ps1"
