import os
import sys
import time
import base64
import inspect
import struct
import pickle
import binascii
import colorama
import random

from lib.Classes import *
from lib.AES256 import AES256
from cryptography.fernet import InvalidToken
from cryptography.fernet import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding



def printLogo(type, version):
	colorama.init(autoreset=True);
	print(colorama.Fore.BLUE+"______________________________________________________".center(os.get_terminal_size().columns-2));
	print("___        _                   ____ _           _".center(os.get_terminal_size().columns-2));
	print("/ ___|  ___ | |_ ___  ___       / ___| |__   __ _| |_".center(os.get_terminal_size().columns-2));
	print("\___ \ / _ \| __/ _ \/ __|_____| |   | '_ \ / _` | __|".center(os.get_terminal_size().columns-2));
	print(" ___) | (_) | || (_) \__ \_____| |___| | | | (_| | |_".center(os.get_terminal_size().columns-2));
	print("|____/ \___/ \__\___/|___/      \____|_| |_|\__,_|\__|".center(os.get_terminal_size().columns-2));
	print(colorama.Fore.BLUE+"______________________________________________________".center(os.get_terminal_size().columns-2));
	print();
	printVersion(type, version);
	
def printVersion(type, version):
	print(colorama.Fore.YELLOW+(f"<<< {type} version:  " + version + " >>>").center(os.get_terminal_size().columns-2));
	print();
	print();

def getTime(getFullTimeAndDate=True):
	timeStruct = time.localtime();
	
	hh = format("%.2d" %timeStruct.tm_hour);
	mm = format("%.2d" %timeStruct.tm_min);
	ss = format("%.2d" %timeStruct.tm_sec);

	dd = format("%.2d" %timeStruct.tm_mday);
	MM = format("%.2d" %timeStruct.tm_mon);
	yyyy = format("%.2d" %timeStruct.tm_year);

	if (getFullTimeAndDate):
		return (hh+":"+mm+":"+ss +' | '+ dd+"/"+MM+"/"+yyyy);
	else:
		return (hh+":"+mm+":"+ss);

def createPrivateKey():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	return private_key;

def privateKeySerialization(private_key):
	private_key_bytes = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	return private_key_bytes;

def privateKeyLoading(private_key_bytes):
	private_key = serialization.load_pem_private_key(
		private_key_bytes,
		password=None,
		backend=default_backend()
	);
	return private_key;

def createPublicKey(private_key):
	public_key = private_key.public_key();
	return public_key;

def publicKeySerialization(public_key):
	public_key_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	);
	return public_key_bytes;

def publicKeyLoading(public_key_bytes):
	public_key = serialization.load_pem_public_key(
		public_key_bytes,
		backend=default_backend()
	);
	return public_key;

def privateKeySign(private_key, signatureMessage):
	signature = private_key.sign(
		signatureMessage,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	);
	return signature;

def publicKeyVerify(public_key, signature, signatureMessage):
	try:
		public_key.verify(signature,
			signatureMessage,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		);
		return True;
	except InvalidSignature:
		return False;

def computeHashSHA256(str):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend());
	digest.update(str.encode());
	sha256 = digest.finalize();
	return sha256;

def rsaEncrypt(public_key, message):
	ciphertext = public_key.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	);
	return ciphertext;

def rsaDecrypt(private_key, ciphertext):
	plaintext = private_key.decrypt(
		ciphertext,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	);
	return plaintext;
	
# def generateSalt():						# Unused
	# salt = os.urandom(32);
	# return salt;

# def getPasswordHashed(salt, password):	# Unused
	# kdf = PBKDF2HMAC(
		# algorithm=hashes.SHA256(),
		# length=32,
		# salt=salt,
		# iterations=100000,
		# backend=default_backend()
	# );

	password_hashed = kdf.derive(password.encode());
	return encode64(password_hashed).decode();
	
def socketSend(socket, dataBytes, cryptoFunc=None, cryptoKey=None):
	dataBytes = pickle.dumps(dataBytes);
	if (cryptoFunc is not None):
		if (cryptoFunc is rsaEncrypt):		#RSA
			dataBytes = cryptoFunc(cryptoKey, dataBytes);		#rsaEncrypt(public_key, message)
		else:								#AES
			dataBytes = cryptoFunc(dataBytes);					#AES256.encrypt(message)
	dataBytes = encode64(dataBytes);
	# Prefix each message with a 4-byte length (network byte order)
	msg = struct.pack('>I', len(dataBytes)) + dataBytes;
	socket.sendall(msg);
	
def socketRecv(socket, expectedDataType, decryptoFunc=None, decryptoKey=None, deserializeErrorBypass=False):
	try:
		raw_msglen = socket.recv(4);
		if (not raw_msglen):
			return None;
		msglen = struct.unpack('>I', raw_msglen)[0];
		dataBytes = socketRecvAll(socket, msglen);
		if (not dataBytes):
			return None;
		if (decryptoFunc is not None):
			if (decryptoFunc is rsaDecrypt):	#RSA
				dataBytes = decryptoFunc(decryptoKey, dataBytes);	#rsaDecrypt(private_key, ciphertext)
			else:								#AES
				dataBytes = decryptoFunc(dataBytes);				#AES256.decrypt(ciphertext)
		return deserializeNetworkMessage(dataBytes, expectedDataType, deserializeErrorBypass);
	except Exception:
		return None;
	
def socketRecvAll(socket, msglen):
	try:
		data = b'';
		n = msglen;
		while (len(data) < n):
			packet = socket.recv(n - len(data));
			if (not packet):
				break;
			data += packet;
		return decode64(data);
	except Exception:
		return None;

def socketSendFile(socket, uploadStatus, dataBytes, cryptoFunc=None, cryptoKey=None):
	dataBytes = pickle.dumps(dataBytes);
	if (cryptoFunc is not None):
		if (cryptoFunc is rsaEncrypt):		#RSA
			dataBytes = cryptoFunc(cryptoKey, dataBytes);		#rsaEncrypt(public_key, message)
		else:								#AES
			dataBytes = cryptoFunc(dataBytes);					#AES256.encrypt(message)
	dataBytes = encode64(dataBytes);
	# Prefix each message with a 4-byte length (network byte order)
	msg = struct.pack('>I', len(dataBytes)) + dataBytes;
	
	sendData = 0;
	msglen = len(dataBytes);
	while (sendData < msglen):
		progressBar(sendData, msglen, uploadStatus);
		sendData = sendData + socket.send(msg);
	progressBar(sendData, msglen, uploadStatus);

def socketRecvFile(socket, downloadStatus, decryptoFunc=None, decryptoKey=None):
	try:
		raw_msglen = socket.recv(4);
		if (not raw_msglen):
			return None;
		msglen = struct.unpack('>I', raw_msglen)[0];
		data = b'';
		while (len(data) < msglen):
			progressBar(len(data), msglen, downloadStatus);
			packet = socket.recv(msglen - len(data));
			if (not packet):
				break;
			data += packet;
		progressBar(len(data), msglen, downloadStatus);
		dataBytes = decode64(data);
		if (decryptoFunc is not None):
			if (decryptoFunc is rsaDecrypt):	#RSA
				dataBytes = decryptoFunc(decryptoKey, dataBytes);	#rsaDecrypt(private_key, ciphertext)
			else:								#AES
				dataBytes = decryptoFunc(dataBytes);				#AES256.decrypt(ciphertext)
		return deserializeNetworkMessage(dataBytes, FileBytesMessage);
	except Exception:
		return None;

def deserializeNetworkMessage(serializedBytes, validationType, deserializeErrorBypass=False):
	deserializedMessage = pickle.loads(serializedBytes);
	if (isinstance(deserializedMessage, validationType)):
		return deserializedMessage;
	else:
		if (not deserializeErrorBypass):
			print("*** Expected network message of type:", validationType);
			print("*** Instead got network message of type:", type(deserializedMessage));
		if (isinstance(deserializedMessage, Message)):
			print("\tEvent occured:", deserializedMessage.type);
			print("\tMore info:", deserializedMessage.msg);
		print();
		return None;
		
def encode64(bytes):
	return base64.urlsafe_b64encode(bytes);

def decode64(bytes):
	return base64.urlsafe_b64decode(bytes);

def progressBar(count, total, status=''):
	bar_len = 70
	filled_len = int(round(bar_len * count / float(total)))

	percents = round(100.0 * count / float(total), 1)
	bar = '=' * filled_len + '-' * (bar_len - filled_len)

	print('[%s] %s%s  ...%s...\r' %(bar, percents, '%', status), end='')
	if (percents == 100.0):
		print('\n\t>>> Done');
		
def getAbsoluteFilePath(filepath):
	if getattr(sys, 'frozen', False):
		return os.path.join(sys._MEIPASS, filepath);
	else:
		return filepath;

def generateRandomNumber(digits):
	return (''.join(["%s" % random.randint(0, 9) for num in range(0, digits)]));


# def getInstanceObjVariables(instanceObj):
	# return [variables for variables in vars(instanceObj) if not variables.startswith('__')];
	
# def getInstanceObjFunctions(instanceObj):
	# return [functTuple[0] for functTuple in inspect.getmembers(instanceObj, predicate=inspect.ismethod)];
	
# def getInstanceObjGlobals(instanceObj):
	# return [globals for globals in dir(instanceObj)
				# if not globals.startswith('__') and
				# not globals in getInstanceObjVariables(instanceObj) and
				# not globals in getInstanceObjFunctions(instanceObj)
			# ];