#!/usr/bin/env python3
parser = ArgumentParser()

parser.add_argument('-t',dest='target',required=True,help='Target to Exploit')
parser.add_argument('-u',dest='username',required=True,help='Username to login')
parser.add_argument('-p',dest='password',required=True,help='Password for login')
parser.add_argument('-v','--version',help='version of this program',action='version',version='%(prog)s 1.0')
args = parser.parse_args()
