python lib/SignVersion.py
pyinstaller --clean --onefile --icon=ico/ChatClient.ico --add-data="audio/message.wav;audio" --add-data="scripts/Updater;scripts" ChatClient.py
pyinstaller --clean --onefile --icon=ico/ChatServer.ico ChatServer.py
pause