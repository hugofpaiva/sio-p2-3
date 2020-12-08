case "$OSTYPE" in
  solaris*) os="SOLARIS" ;;
  darwin*)  os="OSX" ;; 
  linux*)   os="LINUX" ;;
  bsd*)     os="BSD" ;;
  msys*)    os="WINDOWS" ;;
  *)        os="unknown: $OSTYPE" ;;
esac

path=$(pwd)

if [ $os = "OSX" ]
then
osascript <<EOF
tell application "iTerm"
    activate
    set window1 to (create window with default profile)
    tell window1
        launch session "Server"
        tell current session
            write text "cd \"$path\""
            write text "\n"
            write text "source venv/bin/activate"
            write text "\n"
            write text "cd server"
            write text "\n"
            write text "pip3 install -r requirements.txt"
            write text "\n"
            write text "python3 server.py"
            write text "\n"
        end tell
    end tell
    delay 2
    set window2 to (create window with default profile)
    tell window2
        launch session "Viewer"
        tell the current session
            write text "cd \"$path\""
            write text "\n"
            write text "source venv/bin/activate"
            write text "\n"
            write text "cd client"
            write text "\n"  
            write text "pip3 install -r requirements.txt"
            write text "\n"
            write text "python3 client.py"
            write text "\n"
        end tell
    end tell
end tell
EOF
fi

if [ $os = "LINUX" ]
then
gnome-terminal -x bash -c "cd ${path} && source venv/bin/activate && cd server && pip3 install -r requirements.txt && python3 server.py"
sleep 2
gnome-terminal -x bash -c "cd ${path} && source venv/bin/activate && cd client && pip3 install -r requirements.txt && python3 client.py"
fi