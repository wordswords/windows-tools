#!/bin/bash

set -x

# Check if the script is running as root
#
#
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

read -p "MAKE SURE REKORDBOX PROCESS IS KILLED VIA TASK MANAGER! Otherwise a full backup will not happen!"

sudo rsync -azP -e 'sudo ssh -p 608 -i ~david/.ssh/id_rsa' --progress /mnt/d/Rekordbox\ Library\ Files david@hq.local:/mnt3/Rekordbox-backup/
