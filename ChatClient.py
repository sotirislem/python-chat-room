#######################################################################
version = "Thursday, 11 July 2019 | 12:35:17 (GTB Daylight Time +0300)"
#######################################################################

import time
import socket
import threading
import msvcrt
import winsound
import subprocess
import os

from lib.Classes import *
from lib.Methods import *



class CloseConnectionException(Exception):
    pass

def playMessageSound():
	try:
		winsound.PlaySound(getAbsoluteFilePath("audio/message.wav"), winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT | winsound.SND_NOSTOP);
	except RuntimeError:
		pass;

def printCommands():
	print();
	print(colorama.Fore.YELLOW+"\t\t\t* * * * * * COMMANDS * * * * * *");
	print("\t# Type: '"+colorama.Fore.GREEN+"@soundOFF"+colorama.Style.RESET_ALL+"' to DISABLE sound play when new messages arrive!");
	print("\t# Type: '"+colorama.Fore.GREEN+"@soundON"+colorama.Style.RESET_ALL+"' to ENABLE sound play when new messages arrive! (Default)");
	print("\t# Type: '"+colorama.Fore.GREEN+"@users"+colorama.Style.RESET_ALL+"' to check currently connected users!");
	print("\t# Type: '"+colorama.Fore.GREEN+"@exit"+colorama.Style.RESET_ALL+"' to terminate connection with server!");
	print("\t# Type: '"+colorama.Fore.GREEN+"@cls"+colorama.Style.RESET_ALL+"' to clear chat screen!");
	print("\t# Type: '"+colorama.Fore.GREEN+"@web"+colorama.Style.RESET_ALL+"' to open latest message on default web browser!");
	print();

def applyCommand(command):
	global playSoundOnMessageReceive;
	
	print();
	if (command=="@soundOFF".lower()):
		playSoundOnMessageReceive = False;
		print(colorama.Fore.YELLOW+"\t* Sound on new messages is now DISABLED!");
	elif (command=="@soundON".lower()):
		playSoundOnMessageReceive = True;
		print(colorama.Fore.YELLOW+"\t* Sound on new messages is now ENABLED!");
	elif (command=="@cls"):
		os.system('cls');
		printLogo('Client', version);
	elif (command=="@web"):
		if (latestMessage != ""):
			if (latestMessage.find("http")!=-1):
				with tLock:
					print(colorama.Fore.YELLOW+"\t* Loading web page on default browser...");
					time.sleep(3);
					os.startfile(latestMessage);
			else:
				with tLock:
					print(colorama.Fore.YELLOW+"\t* Latest message is not a web page. Message will be 'Googled'...");
					time.sleep(3);
					os.startfile("https://www.google.gr/search?q="+latestMessage);
		else:
			print(colorama.Fore.YELLOW+"\t* No income message found!")
	print();

def main():
	global connection_alive;
	
	printLogo('Client', version);
	
	socket = connectToServer();
	threading.Timer(1, isTyping).start();

	try:
		while(True):
			message = keyboardInspector(socket);
			if (not connection_alive):
				break;

			if (message=="@exit"):
				print("\n\t* Connection with server closed!  Goodbye :)");
				raise(CloseConnectionException);
			elif (message == "~"):
				printCommands();
			elif (message.lower() in client_commands):
				applyCommand(message.lower());
			elif (message != ""):
			
				if (len(message) > 0):
					if (message.lower() in server_commands):
						print();
					else:
						printToTerminal(colorama.Fore.GREEN+"<== "+colorama.Style.RESET_ALL+getTime(False)+"|"+colorama.Fore.GREEN+username+colorama.Style.RESET_ALL+": ", message, False);
					
				msgObject = Client_Message(username, message);
				try:
					socketSend(socket, msgObject, aes256.encrypt);
				except ConnectionError:
					print("\n\t* Error! Connection with server was terminated unexpectedly...  :(");
					raise(CloseConnectionException);
	except CloseConnectionException:
		connection_alive = False;
		input("\nPress Enter to exit...");
	
	socket.close();
	sys.exit();

def connectToServer():
	global connection_alive;
	global aes256;
	global public_key;
	global username;

	host = 'localhost';
	port = 9999;
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
	
	try:
		if (host == None):
			host = input(">>> Please enter ChatServer IP-Address: ");
		print("Trying to connect to server...");
		timeout = 5;
		sock.settimeout(timeout);
		sock.connect((host, port));
		sock.settimeout(None);
	except (socket.timeout, socket.gaierror) as e:
		print("\n* Failed to connect to server!");
		print("\t** Connection timeout, after", timeout, "seconds.");
		print("\t\t*** Server might be down or busy...");
		input("\nPress Enter to exit...");
		sys.exit();
	except Exception as e:
		print("\n* Failed to connect to server!");
		print("\t** " + type(e).__name__ + ": " + str(e));
		input("\nPress Enter to exit...");
		sys.exit();

	print("\t* Connection established.\n")
	try:
		rsaMessage = socketRecv(sock, Server_RSAMessage);
		if (not rsaMessage):
			print("*** Failed to retrive encryption certificates from server!");
			raise(ConnectionError);
		
		public_key = publicKeyLoading(rsaMessage.public_key_bytes);
		
		version_ok = True;
		if (not publicKeyVerify(public_key, rsaMessage.signature, computeHashSHA256(version))):
			print("*** Current client version signature couldn't be verified with server's one!");
			version_ok = False;
		
		aes256 = AES256();
		socketSend(sock, Client_ConnectionRequest(aes256.extract_key(), version_ok), rsaEncrypt, public_key);
		
		connReqAcceptMessage = socketRecv(sock, Server_ConnectionRequestAccept, aes256.decrypt);
		if (not connReqAcceptMessage):
			print("*** Server declined to accept connection request!");
			raise(ConnectionError);
			
		if (not version_ok):
			ans = input(">>> Download updated version from server? ");
			if (ans not in ('y', 'yy', 'yes')):
				raise(ConnectionError);
				
			print("\n*** Requesting newest client version from server...");
			socketSend(sock, Client_VersionUpdateRequest(), aes256.encrypt);
			updated_client = socketRecvFile(sock, "Downloading new version", aes256.decrypt);
			if (not updated_client):
				print("*** Failed to download updated client version from server!");
				raise(ConnectionError);
			else:
				print();
				try:
					with open(os.getcwd()+"\\Updater.bat", "w") as f:
						with open(getAbsoluteFilePath("scripts/Updater")) as updaterFile:
							f.write(updaterFile.read());
					with open(os.getcwd()+"\\ChatClient.TEMP", "wb") as f:
						f.write(updated_client.bytes);
					subprocess.check_call(["attrib", "+H", "Updater.bat"]);
					subprocess.check_call(["attrib", "+H", "ChatClient.TEMP"]);
				except Exception as e:
					print(e);
					input("\n*** Unexpected error! Press Enter to exit...");
					sys.exit();
				
				print("~ Executing Updater script...")
				time.sleep(3);
				os.startfile(os.getcwd()+"\\Updater.bat");	#subprocess.call(os.getcwd()+"\\Updater.bat");	#os.path.expanduser('~')
				sys.exit();
	
		
		if (host not in ('localhost', '127.0.0.1')):
			try:
				while(True):
					otp = input(">>> Please provide OneTimePassword(OTP) to connect to server: ");
					if (not otp):
						print("\t OTP can't be null, try again...\n");
					else:
						break;
			except KeyboardInterrupt:
				print();
				raise(ConnectionError);
		
			socketSend(sock, Client_OneTimePassword(otp), aes256.encrypt);
			otp_ok = socketRecv(sock, Server_OTPOK, aes256.decrypt, None, True);
			if (otp_ok):
				print("\t* OTP OK!");
			else:
				raise(ConnectionError);
			
		while(True):
			try:
				while(True):
					username = input(">>> Username: ");
					if (not username):
						print("\t Username can't be empty, try again...\n");
					else:
						break;
			except KeyboardInterrupt:
				print();
				raise(ConnectionError);
				
			socketSend(sock, Client_ConnectionCredentials(username), aes256.encrypt);
			username_ok = socketRecv(sock, Server_UsernameOK, aes256.decrypt, None, True);
			if (username_ok):
				break;
		
		connEnstablishedMessage = socketRecv(sock, Server_ConnectionEnstablished, aes256.decrypt);
		if (not connEnstablishedMessage):
			print("*** Server failed to enstablish connection!");
			raise(ConnectionError);
		
		print();
		print(("^^^ Connected to server over secure-encrypted connection ^^^").center(os.get_terminal_size().columns-2));
		print(("(Using: RSA_2048 & AES_256_CBC (HMAC authentication) with SHA-256_Hashing)\n\n").center(os.get_terminal_size().columns-2));
		print(("Type '~' to see all of the available chat commands!\n\n").center(os.get_terminal_size().columns-2));
		
		connection_alive = True;
		
		rT = threading.Thread(target=receivingThread, args=(sock,));
		rT.start();
		
		return sock;
	except ConnectionError:
		sock.close();
		print("\t* Connection terminated by server...");
		input("\nPress Enter to exit...");
		sys.exit();

def receivingThread(socket):
	global connection_alive;
	global inputBuffer;
	global latestMessage;
	
	while (connection_alive):
		try:
			msgObject = socketRecv(socket, Message, aes256.decrypt);
			if (msgObject):
				if (isinstance(msgObject, Client_Message)):
					time = getTime(False);
					sender = msgObject.sender;
					data = latestMessage = msgObject.msg;
					
					if (sender in typers):
						with tLock:
							del typers[sender];
						clearIsTyping();

					if (playSoundOnMessageReceive):
						playMessageSound();
					
					printToTerminal(colorama.Fore.YELLOW+"==> "+colorama.Style.RESET_ALL+time+"|"+colorama.Fore.YELLOW+sender+colorama.Style.RESET_ALL+": ", data);
				elif (isinstance(msgObject, Echo)):
					socketSend(socket, msgObject, aes256.encrypt);
				elif (isinstance(msgObject, Client_Typing)):
					with tLock:
						if (msgObject.username not in typers):
							typers[msgObject.username] = 3;
				elif (isinstance(msgObject, Server_Msg)):
					printToTerminal(colorama.Fore.YELLOW+msgObject.msg);
				else:
					raise(ConnectionError);
			else:
				raise(ConnectionError);
		except ConnectionError:
			if (connection_alive):
				connection_alive = False;
				print("\n\t* Error! Connection with server was terminated unexpectedly...  :(");
				print("\nPress Enter to exit...", end='');
			break;

###################### CMD Print Handling ######################
def keyboardInspector(socket):
	global inputBuffer;
	global inputBufferPrefix;
	
	inputBuffer[:] = inputBufferPrefix;
	printInputBuffer();
		
	while(True):
		x = msvcrt.getch();
		
		if (x == b'\x08'):		#Backspace
			if (len(inputBuffer)>1):
				del inputBuffer[-1];
				printInputBuffer();
		elif (x == b'\xe0'):	#DEL
			msvcrt.getch();

			emptyLength = len(inputBuffer)+len(inputBuffer[0]);
			inputBuffer[:] = inputBufferPrefix;
			printInputBuffer(emptyLength);
		elif (x != b'\r'):		#ascii_char
			try:
				inputBuffer.append(x.decode());
				socketSend(socket, Client_Typing(username), aes256.encrypt);
			except UnicodeDecodeError:
				continue;
				
			printInputBuffer();
		else:					#ENTER
			clearIsTyping();
			return ''.join(inputBuffer[1:]);

def printInputBuffer(emptyLength=None):
	if (emptyLength==None):
		print("\r"+" "*(len(inputBuffer)+len(inputBuffer[0])) + "\r"+''.join(inputBuffer), end ='');
	else:
		print("\r"+" "*emptyLength + "\r"+''.join(inputBuffer), end ='');

def printToTerminal(header, msg=None, print_input_buffer=True):
	print("\r"+" "*(len(inputBuffer)+len(inputBuffer[0]))+"\r", end='');
	print(header);
	
	if (msg!=None):
		print("\t"+msg+"\n");
	else:
		print();
		
	if (print_input_buffer):
		printInputBuffer();

def isTyping():
	global typingActive;
	global inputBuffer;
	global inputBufferPrefix;

	if (len(typers)==0):
		if (typingActive):
			clearIsTyping();
	else:
		with tLock:
			typers_sorted_DESC = sorted(typers.items(), key=lambda x: x[1], reverse=True);
			typer = typers_sorted_DESC[0][0];
			typerTimer = typers_sorted_DESC[0][1];
		
			inputBufferCache = inputBuffer[:];
			inputBufferPrefix = ["(@"+typer+" is typing...)>>> "];
			inputBuffer[:] = inputBufferPrefix;
			for x in inputBufferCache[1:]:
				inputBuffer.append(x);
			printInputBuffer();
			
			if (typerTimer-1==0):
				del typers[typer];
			else:
				typers[typer] = typerTimer-1;
			
			typingActive = True;

	if (connection_alive):
		threading.Timer(1, isTyping).start();

def clearIsTyping():
	global typingActive;
	global inputBuffer;
	global inputBufferPrefix;

	with tLock:
		inputBufferCache = inputBuffer[:];
		inputBufferPrefix = [">>> "];
		inputBuffer[:] = inputBufferPrefix;
		for x in inputBufferCache[1:]:
			inputBuffer.append(x);
		printInputBuffer(len(inputBufferCache)+len(inputBufferCache[0]));
		
		typingActive = False;
#######################################################################
inputBuffer = [];
inputBufferPrefix = [">>> "];
tLock = threading.Lock();

connection_alive = False;

username = None;
aes256 = None;
public_key = None;

latestMessage = "";
typingActive = False;
typers = {};

playSoundOnMessageReceive = True;

client_commands = ["@soundOFF".lower(), "@soundON".lower(), "@cls", "@web"];
server_commands = ["@users"];
#######################################################################

if (__name__ == "__main__"):
	main();