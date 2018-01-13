# -*- coding: utf-8 -*-

from io import StringIO
import paramiko
import spur
from spur import SshShell



class CustomSshShell(SshShell):

    def __init__(self, *args, **kwargs):
        self._pt_private_key = kwargs.pop("private_key")
        self._pt_private_key_passphrase = kwargs.pop("private_key_passphrase")
        super(CustomSshShell, self).__init__(**kwargs)

    def _connect_ssh(self):
        if self._client is None:
            if self._closed:
                raise RuntimeError("Shell is closed")
            client = paramiko.SSHClient()
            if self._load_system_host_keys:
                client.load_system_host_keys()
            client.set_missing_host_key_policy(self._missing_host_key)
            private_key = self._pt_private_key

            if private_key is not None:
                private_key = paramiko.RSAKey.from_private_key(
                    StringIO.StringIO(private_key),
                    self._pt_private_key_passphrase)

            client.connect(
                hostname=self._hostname,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=self._connect_timeout,
                sock=self._sock,
                pkey=private_key
            )
            self._client = client
        return self._client

class SSHConnection(object):


    def ssh_connection(self, hostname, port, username, password=None, private_key=None, private_key_passphrase=None):

        self.ssh_client = \
            CustomSshShell(hostname=hostname,
                           username=username,
                           password=password,
                           port=port,
                           private_key=private_key,
                           private_key_passphrase=private_key_passphrase,
                           missing_host_key=spur.ssh.MissingHostKey.warn,
                           shell_type=spur.ssh.ShellTypes.sh
                           )

    def ssh_create_tmp_dir(self):
        self.temp_dir = None
        assert  isinstance(self.ssh_client, SshShell)
        self.temp_dir = self.ssh_client.run(
            ["mktemp", "--directory"], encoding="ascii").output.strip()

    def ssh_remove_tmp_dir(self):
        assert self.temp_dir
        self.ssh_client.run(["rm", "-rf", self.temp_dir])

    def ssh_close(self):
        self.ssh_client.__exit__()

    def ssh_exec_cmd(self,cmd=[]):
        result = self.ssh_client.run(cmd,encoding="ascii", allow_error=True)
        if result.return_code !=0:
            raise result.to_error()
        return result.output

    def get_tmp(self):
        return self.temp_dir

    def scp(self,path_orgin,file):
        with self.ssh_client._connect_sftp() as sftp:
            sftp.put(
                path_orgin+"/"+file,
                self.temp_dir + "/" + file
            )

