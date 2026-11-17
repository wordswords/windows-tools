schtasks /create /tn "Monday 6am Reboot" /tr "shutdown.exe /r /f /t 0" /sc weekly /d MON /st 06:00 /ru SYSTEM /rl HIGHEST
