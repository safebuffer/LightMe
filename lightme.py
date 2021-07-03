#!/usr/bin/env python3
#by hossam mohamed @safe_buffer
import subprocess
import os
import random
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import logging
import shutil

obfuscate_dir = "/tmp/lightme/"
LISTEN_PORT = 8000
BACKGROUD_OBFUSCATION = 200 
MAX_ChildProc = 10
logger = logging.getLogger('LightMe')

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_red(text):
    print(bcolors.FAIL + str(text) + bcolors.ENDC)

def print_green(text):
    print(bcolors.OKGREEN + str(text) + bcolors.ENDC)

def get_powershell_bin():
	def which_powershell():
	    try:
	        powershell_location = subprocess.check_output("which powershell", shell=True)
	    except subprocess.CalledProcessError as e:
	        try:
	            powershell_location = subprocess.check_output("which pwsh", shell=True)
	        except subprocess.CalledProcessError as e:
	            return ""
	        return "pwsh"
	    return "powershell"
	powershell_bin = which_powershell()
	if not powershell_bin:
		print_red("[*] Powershell not found trying to install .... ")
		os.system("sudo apt-get install powershell -y")
		print_red("[*] Start the script again ..")
		exit()
	powershell_bin = which_powershell()
	return powershell_bin

def InvokeObfuscationPath():
	dir_path = os.getcwd()
	path =  os.path.join(dir_path,'Invoke-Obfuscation/Invoke-Obfuscation.psd1')
	return path


def inital_obfuscation(original_powershell_files):
	for powershell_file in original_powershell_files:
		obfuscated_file = os.path.join(obfuscate_dir,powershell_file['filename'])
		logger.info(" obfuscate {} to {} ".format(powershell_file['filename'], obfuscated_file))
		x = threading.Thread(target=obfuscate, args=(powershell_file['fullpath'], obfuscated_file,))
		x.start()
		while int(threading.active_count()) > MAX_ChildProc:
			logger.info(" Hit Maximum Allowed Child process please wait ..")
			time.sleep(3)

def obfuscate(script,out_file):
	ccc = [
		'TOKEN,ALL,1',
		f'STRING,{random.randint(1,3)}',
		f'ENCODING,{random.randint(1,8)}',
	]

	cmds = []
	cmds.append(get_powershell_bin())
	cmds.append('-C')
	cmds.append(f' import-module {InvokeObfuscationPath()};$ErrorActionPreference = "SilentlyContinue";Invoke-Obfuscation -ScriptPath {script} -Command "{random.choice(ccc)}" -Quiet | Out-File -Encoding ASCII {out_file}')
	subprocess_object = subprocess.Popen(cmds,shell=False)
	out, err = subprocess_object.communicate()
	if err:
		logger.debug(f"[-] Error obfuscating {script} {err}")
	subprocess_object.wait()
	return subprocess_object,out_file

def getfiles(dir):
	data = []
	for root, dirs, files in os.walk(dir):
		for file in files:
			if file.endswith("ps1"):
				fileObject = {'fullpath':os.path.join(root,file),'filename':file}
				data.append(fileObject) if fileObject not in data else False
	return data


def obfuscate_random_script(files):
	while True:
		to_obfuscate = random.choice(files)
		obfuscated_file = os.path.join(obfuscate_dir,to_obfuscate['filename'])
		logger.info(f" Obfuscating in background {to_obfuscate['filename']} ")
		obfuscate(to_obfuscate['fullpath'], obfuscated_file)
		time.sleep(BACKGROUD_OBFUSCATION)


class LightMeHTTPServer(BaseHTTPRequestHandler):
	def log_request(self, code='-', size='-'):
		logger.info(f' HTTP Request {code} {self.path}')

	def _set_response(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/plain')
		self.send_header('Server', 'LightMe')
		self.end_headers()

	def do_GET(self):
		self._set_response()
		if self.path == "/":
			self.wfile.write(b"")
		else:
			try:
				requested_file = obfuscate_dir[:-1] + self.path
				if not os.path.isfile(requested_file):
					file_path = base_dir[:-1] + self.path
				else:
					file_path = requested_file
				with open(file_path, 'rb') as file:
					powershell_file = file.read()
					self.wfile.write(powershell_file)
			except Exception as e:
				self.wfile.write(b"404")


def main(options):
	global obfuscate_dir,LISTEN_PORT,BACKGROUD_OBFUSCATION,MAX_ChildProc
	base_dir = options.path
	obfuscate_dir = options.temp
	LISTEN_PORT = int(options.port)
	BACKGROUD_OBFUSCATION = int(options.interval) 
	MAX_ChildProc = int(options.child)

	isdir = os.path.isdir(base_dir)
	if not isdir:
		print_red("[-] Not Found {}".format(base_dir))
		exit()
	try:
		if os.path.isdir(obfuscate_dir):
			shutil.rmtree(obfuscate_dir, ignore_errors=True)
			logger.debug(f" Deleted {obfuscate_dir}")
	except Exception as e:
		logging.exception(" Cannot Remove Directory")
	try:
		if not os.path.isdir(obfuscate_dir):
			os.mkdir(obfuscate_dir)
			logger.debug(" Created Dir {}".format(obfuscate_dir)) 
	except Exception as e:
		logging.exception(" Cannot Create Directory")


	original_powershell_files = getfiles(base_dir)
	print_green("[*] Loaded Powershell Files {}".format(len(original_powershell_files)))
	logging.info("")
	inital_obfuscation(original_powershell_files)

	x = threading.Thread(target=obfuscate_random_script, args=(original_powershell_files,))
	x.start()
	
	for obfuscated_file in original_powershell_files:
		obfuscated_file_path = os.path.join(obfuscate_dir,obfuscated_file['filename'])
		if os.path.isfile(obfuscated_file_path) and not os.stat(obfuscated_file_path).st_size == 0:
			print_green(f"You can reach {obfuscated_file['filename']} via GET /{obfuscated_file['filename']}")

	logger.info(f"Starting http server {LISTEN_PORT}")
	httpd = HTTPServer(('', LISTEN_PORT), LightMeHTTPServer)
	httpd.serve_forever()

if __name__ == '__main__':

	parser = argparse.ArgumentParser(add_help = True, description = "LightMe is a Simple HTTP Server serving Powershell Scripts/Payloads \
		after Obfuscate them and run obfuscation as a service in backgroud\
		in order to keep obfuscate the payloads which giving almost new obfuscated payload with each HTTP request")
	parser.add_argument('-path', action='store', help='Path for powershell scripts')
	parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON',default=False)
	group = parser.add_argument_group('options')
	group.add_argument('-port', action="store", metavar = "int", help='HTTP Port to listen', default=8080)
	group.add_argument('-interval', action="store", metavar = "int", help='Background obfuscation interval in seconds', default=60)
	group.add_argument('-child', action="store", metavar = "int", help='Maximum number of Child Process', default=10)
	group.add_argument('-temp', action="store", metavar = "path", help='Temporary directory to store obfuscated scripts', default="/tmp/lightme/")
	options = parser.parse_args()
	if options.debug:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)
	if len(sys.argv) > 1:
		try:
			main(options)
		except KeyboardInterrupt:
			print_green("Closing Lightme")
			exit()
	else:
		parser.print_help()
		sys.exit(1)