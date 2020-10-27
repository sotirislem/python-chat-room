# Command-line over-network encrypted chat room

A simple command-line chat application made with python that works over-network by using tcp sockets (default port: 9999), allowing unlimited users (default max: 2) to chat among each other. The application consists of two parts, ChatServer and ChatClient. As their names describe, each standalone app is being used for the role of server and client separately. Once the server is up and running many clients can connect to it and chat. Every message sent is being broadcasted to all connected users (clients). All messages between client and server are encrypted through very strong encryptioning by using RSA-2048 and AES-256 algorithms. For extra security, users connecting from the outside network must enter an OneTimePassword (OTP) auto-generated by server in order to be able to connect. Additionally, an update mechanism is being built into the server core so that outdated clients will get auto-updated during connect attempt.

## Required Libraries
```
pyinstaller  -->  pip install pyinstaller
cryptography -->  pip install cryptography
colorama     -->  pip install colorama

Program was tested with the following versions:
-----------------------
Python       -->  3.6.1
-----------------------
pyinstaller  -->  4.0
cryptography -->  1.9
colorama     -->  0.4.4
-----------------------
```

## How to compile
```
Use 'create_executables.bat' file to compile source code (.py) into windows executables (.exe).
The successful execution of the script creates 2 files (ChatServer.exe, ChatClient.exe) in dist folder.

The program is already pre-compiled in dist folder.
```

## Supported Operating Systems
```
So far, ChatClient can only work on Windows Operating Systems, since it is using the 'msvcrt' library from the MS VC++ runtime in order to handle text in cmd.
```