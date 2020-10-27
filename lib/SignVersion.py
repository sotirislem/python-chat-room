import time
# import random
# import string


# def generateRandomSequence(length):
	# return (''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(length)));
	
# def createSignatureTag():
	# signatureTag = generateRandomSequence(57);
	# signature = "signature = \"" + signatureTag + "\"";
	# return signature;

def createVersionTag():
	timeTag = time.strftime("%A, %d %B %Y | %H:%M:%S (%Z %z)", time.localtime(time.time()));
	version = "version = \"" + timeTag + "\"";
	return version;


def main():
	version = createVersionTag();
	# signature = createSignatureTag();
	
	with open("ChatServer.py", 'r+') as f:
		text = f.read();
		text = text[text.find("import"):]
		f.seek(0);
		f.write("#######################################################################\n");
		f.write(version+"\n");
		# f.write(signature+"\n");
		f.write("#######################################################################\n\n");
		f.write(text);

	with open("ChatClient.py", 'r+') as f:
		text = f.read();
		text = text[text.find("import"):]
		f.seek(0);
		f.write("#######################################################################\n");
		f.write(version+"\n");
		# f.write(signature+"\n");
		f.write("#######################################################################\n\n");
		f.write(text);

	print("* ChatServer.py & ChatClient.py successfully signed with a new version!");
	# input("\nPress enter to continue...");

if (__name__ == "__main__"):
	main();