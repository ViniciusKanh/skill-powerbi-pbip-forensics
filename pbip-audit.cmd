@echo off
rem Power BI PBIP Forensics - auditoria em um clique.
rem Uso: arraste a pasta do projeto PBIP sobre este arquivo, ou:  pbip-audit.cmd "C:\caminho\do\projeto" [opcoes]
setlocal
if "%~1"=="" (
  echo Arraste a pasta do projeto PBIP sobre este arquivo ou informe o caminho.
  echo Exemplo: pbip-audit.cmd "C:\BI\MeuRelatorio" --lang pt-BR
  pause
  exit /b 2
)
set "PYTHONPATH=%~dp0src"
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>nul || (
  echo Python 3.11+ nao encontrado. Instale com: winget install -e --id Python.Python.3.12
  pause
  exit /b 2
)
set "PROJ=%~1"
shift
py -3 -m pbip_forensics run --project "%PROJ%" --open --lang pt-BR %1 %2 %3 %4 %5 %6 %7 %8
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" if not "%RC%"=="1" pause
exit /b %RC%
