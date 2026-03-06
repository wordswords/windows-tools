Set-ExecutionPolicy Unrestricted -Scope Process -Force
Start-Process powershell.exe -PassThru -ArgumentList "-executionpolicy bypass -WindowStyle Hidden -File C:\Users\conta\My Documents\Win11Debloat.ps1 -Silent -RunDefaults" -Verb RunAs
