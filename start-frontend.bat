@echo off
REM Starts the MCP-Sentinel dashboard on http://localhost:5173
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo Installing frontend packages...
    call npm install || goto :error
)
call npm run dev
goto :eof
:error
echo Setup failed. See the messages above.
pause
