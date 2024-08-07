@echo off
call fasm.exe basic.asm
call basic.exe
echo %errorlevel%