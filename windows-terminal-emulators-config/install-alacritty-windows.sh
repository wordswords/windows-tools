#!/bin/bash

set -x
set -e

sudo rm -rf "/mnt/C/Program Files/alacritty"
sudo mkdir -p "/mnt/C/Program Files/alacritty"
sudo wget "https://github.com/alacritty/alacritty/releases/download/v0.13.2/Alacritty-v0.13.2-portable.exe" -O "/mnt/C/Program Files/alacritty/Alacritty-v0.13.2-portable.exe"
mkdir -p /mnt/c/Users/conta/AppData/Roaming/alacritty
cp ~/.dotfiles/windows-tools/windows-terminal-emulators-config/windows-alacritty.toml /mnt/c/Users/conta/AppData/Roaming/alacritty/alacritty.toml
echo "Now you can run Alacritty by running C:\Program Files\alacritty\Alacritty-v0.13.2-portable.exe from within windows and it will launch WSL"

