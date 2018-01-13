import argparse
import getpass
import json
import sys
from sshClient import SSHConnection
from paramiko import ssh_exception

parser = argparse.ArgumentParser()
parser.add_argument("login_name",
                    help="your ssh username",type=str)
parser.add_argument("-H","--hostname", help="target host ip",default="localhost")
parser.add_argument("-p", "--port",
                    help="ssh port",default=22)
parser.add_argument("-i", "--identity_file",
                    help="""Selects a file from which the identity (private key) for public key authentication is read.""")
#~/.ssh/id_rsa
parser.add_argument("hostname",
                    help="target hostname or ip",type=str)
args = parser.parse_args()
#parser.add_argument("-p", "--password",
#                    help="your mooncloud username password")
password=None
private_key=None
private_key_passphrase=None
if args.identity_file is None:
    p = getpass.getpass(prompt='ssh password: ')
    password=p
else:
    pass
    #get identity key

hostname=args.hostname
username=args.login_name
port=args.port

ssh_client =SSHConnection()
ssh_client.ssh_connection(
            hostname=hostname,
            username=username,
            port=port,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase
            )

#sudo -n true
try:
    ssh_client.ssh_exec_cmd(["echo","hello"])
except Exception as e:
    print(e)
    sys.exit()
try:
    ssh_client.ssh_exec_cmd(["sudo","-n","true"])

except Exception as e:
    print(e)
    sys.exit("username must be in sudoers with NOPASSWD enabled")
try:
    ssh_client.ssh_create_tmp_dir()
    ssh_client.scp(".","spectre-meltdown-checker.sh")
    to_parse=ssh_client.ssh_exec_cmd(["sudo","sh", ssh_client.get_tmp()+"/spectre-meltdown-checker.sh","--batch","json"])
    ssh_client.ssh_remove_tmp_dir()
    vulns=json.loads(to_parse)
    result={}
    set_result=True
    for v in vulns:
        if v.get("NAME","")=="SPECTRE VARIANT 1":

                result["spectre v1"]=v
        elif v.get("NAME","")=="SPECTRE VARIANT 2":
            result["spectre v2"] = v
        elif v.get("NAME","")=="MELTDOWN":
            result["meltdown"]=v
        if v.get("VULNERABLE",False)==True:
            set_result=False
    print ("VULNERABLE:"+str(not(set_result)))

    print(result.get("spectre v1"))
    print(result.get("spectre v2"))
    print(result.get("meltdown"))
    #ssh_client.ssh_remove_tmp_dir()
    ssh_client.ssh_close()
except Exception as e:
    print(e)
    sys.exit("execution error")



#print("echo -e '"+script+"'")
#with ssh_client._connect_sftp() as sftp:
#    sftp.put("spectre-meltdown-checker.sh","/tmp/spectre-meltdown-checker.sh")

#
#_stdin, _stdout, _stderr = ssh_client.exec_command("sudo sh /tmp/spectre-meltdown-checker.sh --batch json")
#out = _stdout.readlines()
#print (out)
#
#_stdin, _stdout, _stderr = ssh_client.exec_command("rm /tmp/spectre-meltdown-checker.sh")
#out = _stdout.readlines()
#print (out)
#