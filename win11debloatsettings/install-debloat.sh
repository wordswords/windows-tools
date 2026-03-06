#!/bin/bash

set -e
set -x

mkdir -p /tmp/Win11Debloat
rm -rf /tmp/Win11Debloat
git clone git@github.com:Raphire/Win11Debloat.git /tmp/Win11Debloat
sudo mkdir -p /mnt/c/Users/conta/Documents/Win11Debloat
sudo mv /tmp/Win11Debloat/* '/mnt/c/Users/conta/Documents/Win11Debloat/'
sudo cp ./DefaultSettings.json '/mnt/c/Users/conta/Documents/Win11Debloat'
sudo mkdir -p '/mnt/c/Users/conta/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/'
sudo cp ./documents-dir-ps1-to-run-debloat.ps1 '/mnt/c/Users/conta/Documents/Win11Debloat'
sudo cp ./startup-dir-bat-to-run-ps1-file.bat '/mnt/c/Users/conta/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/'


