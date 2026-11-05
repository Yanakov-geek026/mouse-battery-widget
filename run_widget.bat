@echo off
rem Лаунчер виджета заряда мыши ARDOR Phantom PRO v2 (без консольного окна)
setlocal
set "PY=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\pythonw.exe"
if exist "%PY%" goto run
set "PY=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"
if exist "%PY%" goto run
where pythonw.exe >nul 2>nul
if %errorlevel%==0 (
    set "PY=pythonw.exe"
    goto run
)
set "PY=python.exe"
:run
start "" "%PY%" "%~dp0mouse_battery_widget.py"
