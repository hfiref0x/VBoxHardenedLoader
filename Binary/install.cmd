REM Append full patch to tdl.exe/tsugumi.sys and run this batch file elevated
@echo off
echo Run TDL (tdl.exe tsugumi.sys)
pause
tdl.exe tsugumi.sys
echo Run loader
pause
call loader.cmd
net start vboxdrv