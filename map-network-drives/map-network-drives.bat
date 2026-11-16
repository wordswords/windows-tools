net use B: /delete
net use G: /delete
net use F: /delete
net use J: /delete
net use K: /delete
net use L: /delete
net use M: /delete
net use N: /delete
net use Q: /delete
net use O: /delete
net use P: /delete
net use T: /delete
net use X: /delete
net use Y: /delete
net use Z: /delete

set h=192.168.1.200

net use G: \\%h%\games /user:guest ""
net use J: \\%h%\incominggames /user:guest ""
net use K: \\%h%\incomingmusic /user:guest ""
net use L: \\%h%\incomingpapers /user:guest ""
net use M: \\%h%\music /user:guest ""
net use P: \\%h%\comics /user:guest ""
net use Q: \\%h%\comicsclean /user:guest ""
net use T: \\%h%\incomingtvvideo /user:guest ""
net use N: \\%h%\incomingebooks /user:guest ""
net use O: \\%h%\incomingcomics /user:guest ""
net use Y: \\%h%\incomingmiscaudio /user:guest ""
net use X: \\%h%\incomingmiscvideo /user:guest ""
net use Z: \\%h%\incomingscratch /user:guest ""

