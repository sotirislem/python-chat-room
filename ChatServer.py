#######################################################################
version = "Thursday, 11 July 2019 | 12:35:17 (GTB Daylight Time +0300)"
#######################################################################

import socket
import threading
import os

from lib.Classes import *
from lib.Methods import *



def socketAcceptThread():
	global total_available_ports;
	global usersSockets;
	global socketCryptors;

	host = '127.0.0.1';
	port = 9999;

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		sock.bind((host, port));
		sock.listen(0);
	except Exception as e:
		print("* " + type(e).__name__ + ": " + str(e));
		input("\nPress enter to exit...");
		sys.exit();
	
	print(f"* Server started at TCP port: {port}");
	while (total_available_ports != 0):
		try:
			print(getTime()+" --> Total available user ports: ", total_available_ports, ", awaiting for connections...");
			
			newSocket, addr = sock.accept();
			print(getTime()+" --> Accepted new connection from", addr);
			
			socketSend(newSocket, Server_RSAMessage(public_key_bytes, privateKeySign(private_key, computeHashSHA256(version))));
			
			connReqMessage = socketRecv(newSocket, Client_ConnectionRequest, rsaDecrypt, private_key);
			if (not connReqMessage):
				raise(ConnectionError);
			else:
				if (not connReqMessage.ver_ok):
					print(getTime()+" --> Client version is outdated.");
			
			client_aes256 = AES256(connReqMessage.aes_key);
			socketSend(newSocket, Server_ConnectionRequestAccept(), client_aes256.encrypt);
			
			if (not connReqMessage.ver_ok):
				if (not socketRecv(newSocket, Client_VersionUpdateRequest, client_aes256.decrypt)):
					raise(ConnectionError);
				else:
					print(getTime()+" --> Client requested newest client version. Starting uploading...");
					with open(client_path, 'rb') as f:
						updated_client_bytes = f.read();
					socketSendFile(newSocket, "Uploading ChatClient.exe", FileBytesMessage(updated_client_bytes), client_aes256.encrypt);
					print(getTime()+" --> Client received newest version successfully! Terminating current session.");
					newSocket.close();
					continue;
			
			
			if (addr[0] not in ('localhost', '127.0.0.1')):
				otp = generateRandomNumber(8);
				print(getTime()+" --> OneTimePassword:", otp);
				otpMessage = socketRecv(newSocket, Client_OneTimePassword, client_aes256.decrypt);
				if (not otpMessage):
						raise(ConnectionError);
				else:
					if (otp == otpMessage.otp):
						socketSend(newSocket, Server_OTPOK(), client_aes256.encrypt);
						print(getTime()+" --> OTP successfully matched!");
					else:
						socketSend(newSocket, Server_OTPNotOK("Given OTP '" + otpMessage.otp + "' didn't match server's one '" + otp + "'"), client_aes256.encrypt);
						print(getTime()+" --> OTP mismatch error!");
						raise(ConnectionError);
			else:
				print(getTime()+" --> OTP is not required for 'localhost' connection!");
			
			validUsernameAttempt = 0;
			while (True):
				validUsernameAttempt = validUsernameAttempt + 1;
				print(getTime()+f" --> Awaiting new user to provide a username... (Attempt: No{validUsernameAttempt})");
				connCredentialsMessage = socketRecv(newSocket, Client_ConnectionCredentials, client_aes256.decrypt);
				if (not connCredentialsMessage):
					raise(ConnectionError);
				with tLock:
					if (connCredentialsMessage.username in usersSockets):
						print(getTime()+" --> Given username '", connCredentialsMessage.username, "' is already in use!");
						socketSend(newSocket, Server_UsernameNotOK("Given username '" + connCredentialsMessage.username + "' is already in use!"), client_aes256.encrypt);
					else:
						socketSend(newSocket, Server_UsernameOK(), client_aes256.encrypt);
						break;
			
			addNewClient(connCredentialsMessage.username, newSocket, client_aes256, addr);
		except ConnectionError:
			print(getTime()+" --> Connection from", addr, "terminated unexpectedly!");
			newSocket.close();
			continue;
	
	print(getTime()+f" --> No more user ports available (0/{len(usersSockets)} free)! Stop accepting new connections...");
	print(f"* Server stopped listening for new connections!");

def addNewClient(username, socket, aes256, addr):
	global total_available_ports;
	
	socketSend(socket, Server_ConnectionEnstablished(), aes256.encrypt);
	
	print(getTime()+" --> User '", username, "' is now connected from", addr);
	broadcast(Server_Msg("* User '" + username + "' is now connected."));
	
	with tLock:
		usersSockets[username] = socket;
		socketCryptors[socket] = aes256;

	total_available_ports -= 1;
	t = threading.Thread(target=clientSocketThread, args=(username, socket, aes256));
	t.start();

def broadcast(msgObject, exceptSocket=None):
	with tLock:
		for user, userSocket in usersSockets.items():
			if (userSocket != exceptSocket):
				socketSend(userSocket, msgObject, socketCryptors[userSocket].encrypt);

def clientSocketThread(username, socket, aes256):
	global total_available_ports;
	global acceptThread;
	global usersSockets;
	global socketCryptors;

	echoClient(username, socket, aes256);

	while (True):
		try:
			msgObject = socketRecv(socket, Message, aes256.decrypt);
			if (msgObject):
				if (isinstance(msgObject, Echo)):
					continue;
				else:
					if (msgObject.msg in server_commands):
						msg = parseCommand(msgObject.msg, username, socket);
						socketSend(socket, Server_Msg(msg), aes256.encrypt);
					else:
						broadcast(msgObject, socket);
			else:
				raise(ConnectionError);
		except ConnectionError:
			socket.close();
			
			with tLock:
				del usersSockets[username];
				del socketCryptors[socket];

			total_available_ports += 1;
			broadcast(Server_Msg("* User '" + username + "' has been disconnected."));
			print(getTime()+" --> User '", username, "' disconnected from server!");
			
			if (not acceptThread.isAlive()):
				acceptThread = threading.Thread(target=socketAcceptThread);
				acceptThread.start();
			else:
				print(getTime()+" --> Total available user ports: ", total_available_ports, ", awaiting for connections...");
			break;

def parseCommand(command, username, socket):
	msg = "";

	if (command == "@users"):
		msg += "\t* Currently connected users:\n";
		msg += "\t\t\t\t\t"+username+" (You)\n";
		with tLock:
			for user, userSocket in usersSockets.items():
				if (socket != userSocket):
					msg += "\t\t\t\t\t"+user+"\n";
			msg = msg[0:-1];

	return msg;

def echoClient(username, socket, aes256):
	try:
		socketSend(socket, Echo(), aes256.encrypt);
	except ConnectionError:
		pass;
	except OSError:
		pass;
		
	if (username in usersSockets):
		t = threading.Timer(ECHO_TIMER_SEC_INTERVAL, echoClient, args=(username, socket, aes256));
		t.start();


def main():
	global acceptThread;
	
	printLogo('Server', version);
	
	acceptThread = threading.Thread(target=socketAcceptThread);
	acceptThread.start();


#######################################################################
ECHO_TIMER_SEC_INTERVAL = 60;
total_available_ports = 2;
acceptThread = None;
tLock = threading.Lock();

private_key = createPrivateKey();
public_key = createPublicKey(private_key);
public_key_bytes = publicKeySerialization(public_key);

usersSockets = {};
socketCryptors = {};

client_path = "ChatClient.exe";
server_commands = ["@users"];
#######################################################################

if (__name__ == "__main__"):
	main();