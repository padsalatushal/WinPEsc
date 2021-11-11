#!/usr/bin/env python3
from argparse import ArgumentParser


def get_args():
	parser = ArgumentParser(description="WinPEsc helps to maintain access to windows machine and have some other cool features like UAC Disable,Firewall Disable,Dumping Credentials,etc.",usage='python3 %(prog)s -t Target -u Username -P Password',epilog='Example: python3 %(prog)s 192.168.101.14 admin P@$$w0rd123')

	parser.add_argument('-t',dest='target',required=True,help='Target to Exploit')
	parser.add_argument('-u',dest='username',required=True,help='Username to login')
	parser.add_argument('-p',dest='password',required=True,help='Password for login')
	parser.add_argument('-v','--version',help='version of this program',action='version',version='%(prog)s 1.0')
	args = parser.parse_args()

	return args

args = get_args()

target = args.target
username = args.username
password = args.password
#print(target,username,password)


