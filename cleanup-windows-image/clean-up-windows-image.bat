DISM.exe /Online /Cleanup-image /Scanhealth
DISM.exe /Online /Cleanup-image /Restorehealth
DISM.exe /Online /Cleanup-image /startcomponentcleanup
sfc /scannow
@echo off
echo Batch file finished. Please press any key to Exit...
pause

