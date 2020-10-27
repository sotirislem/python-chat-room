class Message(object):
	def __init__(self, type, msg=None):
		self.type = type;
		self.msg = msg;
		
class FileBytesMessage(Message):
	def __init__(self, bytes):
		Message.__init__(self, "FILE_TRANSFER");
		self.bytes = bytes;

class Echo(Message):
	def __init__(self):
		Message.__init__(self, "ECHO");
		
class Client_Message(Message):
	def __init__(self, username, msg):
		Message.__init__(self, "TEXT_MESSAGE", msg);
		self.sender = username;

class Client_ConnectionRequest(Message):
	def __init__(self, aes_key, ver_ok):
		Message.__init__(self, "CLIENT_C_REQ");
		self.aes_key = aes_key;
		self.ver_ok = ver_ok;

class Client_VersionUpdateRequest(Message):
	def __init__(self):
		Message.__init__(self, "CLIENT_VERSION_UPDATE_REQUEST");
		
class Client_OneTimePassword(Message):
	def __init__(self, otp):
		Message.__init__(self, "CLIENT_ONE_TIME_PASSWORD");
		self.otp = otp;

class Client_ConnectionCredentials(Message):
	def __init__(self, username):
		Message.__init__(self, "CLIENT_CREDENTIALS");
		self.username = username;

class Client_Typing(Message):
	def __init__(self, username):
		Message.__init__(self, "CLIENT_TYPING");
		self.username = username;

class Server_RSAMessage(Message):
	def __init__(self, public_key_bytes, signature):
		Message.__init__(self, "SERVER_RSA_CERTIFICATE");
		self.public_key_bytes = public_key_bytes;
		self.signature = signature;
		
class Server_ConnectionRequestAccept(Message):
	def __init__(self):
		Message.__init__(self, "SERVER_CONNECTION_REQUEST_ACCEPT");
		
class Server_OTPNotOK(Message):
	def __init__(self, msg):
		Message.__init__(self, "SERVER_OTP_NOT_OK", msg);
		
class Server_OTPOK(Message):
	def __init__(self):
		Message.__init__(self, "SERVER_OTP_OK");
		
class Server_UsernameNotOK(Message):
	def __init__(self, msg):
		Message.__init__(self, "SERVER_USERNAME_NOT_OK", msg);
		
class Server_UsernameOK(Message):
	def __init__(self):
		Message.__init__(self, "SERVER_USERNAME_OK");
		
class Server_ConnectionEnstablished(Message):
	def __init__(self):
		Message.__init__(self, "SERVER_CONNECTION_ENSTABLISHED");

class Server_Msg(Message):
	def __init__(self, msg):
		Message.__init__(self, "SERVER_MESSAGE", msg);