sudo rsync -azP -e 'sudo ssh -p 608 -i ~david/.ssh/id_rsa' --progress $1 david@hq.local:~


